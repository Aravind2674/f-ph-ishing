"""
ThreatFusion – Predictive Vulnerability Chaining (Reasoning Engine)
==================================================================

This module implements the logical chainer that maps vulnerabilities to attack graphs:
1. Loads EPSS scores, CISA KEV status, and Exploit-DB ID mapping from the project root directory.
2. Queries the local Ollama instance (e.g. Llama-3) to determine vulnerability pre-conditions and post-conditions.
3. Builds a directed graph using networkx, weights edges based on CVSS/EPSS exploitability metrics, and calculates the attack paths.
"""

from __future__ import annotations

import asyncio
import csv
import logging
import time
from pathlib import Path
from uuid import uuid4
import httpx
import networkx as nx
from typing import Optional, Any
from app.models.schemas import AttackChainNode, AttackPath, CVEDetail, ExposureCve

logger = logging.getLogger(__name__)

# Path declarations (assuming datasets are in the project root)
BASE_DIR = Path(__file__).resolve().parents[4]
EPSS_PATH = BASE_DIR / "epss_scores-2026-07-12.csv"
KEV_PATH = BASE_DIR / "known_exploited_vulnerabilities.csv"
EXPLOITDB_PATH = BASE_DIR / "files_exploits.csv"
OLLAMA_API_URL = "http://localhost:11434/api/generate"
_OLLAMA_RETRY_SECONDS = 60.0     # how long a failed Ollama probe is remembered
_CONDITION_LOOKUPS = 4           # concurrent per-CVE condition lookups


class VulnerabilityChainer:
    """The vulnerability chaining logic coordinator."""

    def __init__(self) -> None:
        self.epss_cache: dict[str, float] = {}      # legacy snapshot only; a CVE missing from it is UNKNOWN, not 0.0
        self.kev_cache: set[str] = set()
        self.exploit_db_cache: dict[str, str] = {}
        self._initialized = False
        self._epss_kev_loaded = False
        self._exploitdb_loaded = False
        # Ollama is an optional local LLM. When it is unreachable we remember that for a while instead of paying
        # a connection attempt (and its timeout) for every single CVE.
        self._ollama_down_until: float = 0.0

    def initialize(self, *, legacy_epss_kev: bool = True) -> None:
        """Parse the local threat databases into memory (lazy, once).

        ``legacy_epss_kev=False`` skips the EPSS/KEV CSV *snapshots*: a scan that already holds live EPSS/KEV evidence
        (B11) passes it to :meth:`build_and_solve_chain` and needs only the Exploit-DB mapping.
        """
        if self._initialized:
            return
        if legacy_epss_kev:
            self._ensure_epss_kev()
        self._ensure_exploit_db()
        self._initialized = legacy_epss_kev or self._epss_kev_loaded

    def _ensure_epss_kev(self) -> None:
        if not self._epss_kev_loaded:
            self._load_epss_kev()
            self._epss_kev_loaded = True

    def _ensure_exploit_db(self) -> None:
        if not self._exploitdb_loaded:
            self._load_exploit_db()
            self._exploitdb_loaded = True

    def _load_epss_kev(self) -> None:
        """EPSS + KEV from the CSV snapshots in the repo root (legacy / offline fallback)."""
        logger.info("Loading EPSS/KEV snapshots...")

        # EPSS CSV
        if EPSS_PATH.exists():
            try:
                with open(EPSS_PATH, "r", encoding="utf-8") as f:
                    # Skip comment header line
                    line = f.readline()
                    if line.startswith("#"):
                        # Next line is column headers
                        f.readline()
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            # Row format: cve, epss, percentile
                            self.epss_cache[row[0].strip().upper()] = float(row[1])
                logger.info("Loaded %d EPSS scores.", len(self.epss_cache))
            except Exception as e:
                logger.error("Failed to parse EPSS file: %s", e)
        else:
            logger.warning("EPSS catalog not found at %s", EPSS_PATH)

        # CISA KEV CSV
        if KEV_PATH.exists():
            try:
                with open(KEV_PATH, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        cve_id = row.get("cveID", "").strip().upper()
                        if cve_id:
                            self.kev_cache.add(cve_id)
                logger.info("Loaded %d CISA KEV entries.", len(self.kev_cache))
            except Exception as e:
                logger.error("Failed to parse CISA KEV catalog: %s", e)
        else:
            logger.warning("CISA KEV catalog not found at %s", KEV_PATH)

    def _load_exploit_db(self) -> None:
        """Exploit-DB CVE → exploit id mapping from the CSV in the repo root."""
        logger.info("Loading the Exploit-DB mapping...")

        if EXPLOITDB_PATH.exists():
            try:
                with open(EXPLOITDB_PATH, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        exploit_id = row.get("id", "").strip()
                        codes = row.get("codes", "")
                        # The codes column can contain multiple CVE references separated by semicolons
                        if codes and exploit_id:
                            for code in codes.split(";"):
                                clean_code = code.strip().upper()
                                if clean_code.startswith("CVE-"):
                                    self.exploit_db_cache[clean_code] = exploit_id
                logger.info("Loaded %d Exploit-DB mapping entries.", len(self.exploit_db_cache))
            except Exception as e:
                logger.error("Failed to parse Exploit-DB CSV: %s", e)
        else:
            logger.warning("Exploit-DB catalog not found at %s", EXPLOITDB_PATH)

    async def get_pre_and_post_conditions(self, cve_id: str, description: str) -> tuple[list[str], list[str]]:
        """Queries the local Ollama LLM to semantic-parse preconditions and postconditions.
        If Ollama is unreachable, it defaults to a safe rule-based heuristic fallback.
        """
        prompt = (
            f"Given the following vulnerability description for {cve_id}:\n"
            f"\"{description}\"\n\n"
            f"Identify the technical conditions required to exploit it (Pre-conditions) and the outcome/privileges gained after exploit (Post-conditions).\n"
            f"Provide the response ONLY as a JSON payload in this exact format:\n"
            f"{{\n"
            f"  \"pre_conditions\": [\"example_precondition\"],\n"
            f"  \"post_conditions\": [\"example_postcondition\"]\n"
            f"}}\n"
            f"Ensure the list items are single-word keys (like 'network_access', 'auth_required', 'local_file_read', 'remote_code_execution', 'privilege_escalation')."
        )
        
        if time.monotonic() >= self._ollama_down_until:
            try:
                # A *connect* failure (nothing listening) should cost milliseconds, not the 5 s read budget.
                async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=0.5)) as client:
                    response = await client.post(
                        OLLAMA_API_URL,
                        json={
                            "model": "llama3",
                            "prompt": prompt,
                            "stream": False,
                            "format": "json"
                        }
                    )
                    if response.status_code == 200:
                        payload = response.json()
                        import json
                        text_response = payload.get("response", "{}")
                        parsed = json.loads(text_response)
                        return parsed.get("pre_conditions", []), parsed.get("post_conditions", [])
            except Exception:
                # Ollama is not running / timed out: remember it for a minute so the remaining CVEs go straight to
                # the heuristic below instead of each paying for the same failed attempt.
                self._ollama_down_until = time.monotonic() + _OLLAMA_RETRY_SECONDS

        # Heuristic rules mapping typical keyword signatures in vulnerability summaries
        desc_lower = description.lower()
        pre = ["network_access"]
        post = ["info_disclosure"]

        if "authenticated" in desc_lower or "authentication" in desc_lower or "credentials" in desc_lower:
            pre.append("auth_required")
        if "local" in desc_lower or "privilege" in desc_lower:
            pre.append("local_access")

        if "remote code execution" in desc_lower or "rce" in desc_lower or "execute arbitrary code" in desc_lower:
            post = ["remote_code_execution"]
        elif "path traversal" in desc_lower or "directory traversal" in desc_lower or "read file" in desc_lower:
            post = ["local_file_read"]
        elif "privilege escalation" in desc_lower or "elevate" in desc_lower:
            post = ["privilege_escalation"]
        elif "bypass" in desc_lower or "authorization" in desc_lower:
            post = ["auth_bypass"]

        return pre, post

    async def build_and_solve_chain(self, cves: list[CVEDetail],
                                    intel: Optional[dict[str, ExposureCve]] = None) -> list[AttackPath]:
        """Core chainer solving routing paths using NetworkX directed graph.

        ``intel`` is the per-CVE exploitation evidence a scan already collected (EPSS from FIRST.org, KEV from the local
        catalogue; ``ExposureAssessment.cves``). When given, it replaces the CSV snapshots; without it the snapshots are the
        (offline) fallback. Either way an unknown EPSS is ``None`` and contributes nothing — never an invented 0.0.
        """
        self.initialize(legacy_epss_kev=intel is None)

        if not cves:
            return []

        # Hydrate raw NVD CVEs with local threat intelligence details
        gate = asyncio.Semaphore(_CONDITION_LOOKUPS)

        async def conditions(cve: CVEDetail) -> tuple[list[str], list[str]]:
            async with gate:
                return await self.get_pre_and_post_conditions(cve.cve_id.upper(), cve.description)

        # The first lookup runs alone: it finds out whether Ollama is reachable, so a failure is already known (and the
        # heuristic used straight away) when the remaining CVEs are looked up together.
        first = await conditions(cves[0])
        rest = await asyncio.gather(*(conditions(c) for c in cves[1:]))
        all_conditions = [first, *rest]

        hydrated_nodes: list[AttackChainNode] = []
        for cve, (pre_conds, post_conds) in zip(cves, all_conditions):
            cve_id = cve.cve_id.upper()
            if intel is not None and cve_id in intel:
                epss = intel[cve_id].epss                      # None = unknown
                in_kev = bool(intel[cve_id].in_kev)            # None (feed unavailable) is not "listed"
            else:
                epss = self.epss_cache.get(cve_id)             # None = unknown (NOT 0.0)
                in_kev = cve_id in self.kev_cache
            exploit_db_id = self.exploit_db_cache.get(cve_id)

            hydrated_nodes.append(AttackChainNode(
                cve_id=cve_id,
                cvss_score=cve.cvss_v3_score,
                epss_score=epss,
                is_in_kev=in_kev,
                exploit_db_id=exploit_db_id,
                pre_conditions=pre_conds,
                post_conditions=post_conds,
                description=cve.description
            ))

        # Build NetworkX directed graph
        G = nx.DiGraph()
        
        # Start state
        G.add_node("internet_access", type="state")
        
        # Add vulnerability nodes and transition edges
        for node in hydrated_nodes:
            # Nodes are represented by their CVE ID
            G.add_node(node.cve_id, type="vuln", data=node)
            
            # Map pre-conditions as incoming edges to the CVE
            for pre in node.pre_conditions:
                if pre == "network_access":
                    G.add_edge("internet_access", node.cve_id)
                else:
                    G.add_node(pre, type="state")
                    G.add_edge(pre, node.cve_id)
                    
            # Map post-conditions as outgoing edges from the CVE to system states
            for post in node.post_conditions:
                G.add_node(post, type="state")
                G.add_edge(node.cve_id, post)

        # Solve paths from "internet_access" to high-value outcomes (e.g. RCE)
        target_states = ["remote_code_execution", "local_file_read", "privilege_escalation", "auth_bypass"]
        paths_found: list[AttackPath] = []

        for target in target_states:
            if G.has_node(target):
                try:
                    # Find all simple paths from internet access to the target state
                    for path in nx.all_simple_paths(G, source="internet_access", target=target):
                        # Filter out state labels to only collect the sequence of vulnerability nodes traversed
                        vuln_nodes_in_path = [G.nodes[n]["data"] for n in path if G.nodes[n].get("type") == "vuln"]
                        if not vuln_nodes_in_path:
                            continue
                        
                        # Joint risk: P(A union B union C...) over the CVEs that have evidence. A CVE with no CVSS, no EPSS
                        # and no KEV listing is *unrated*: it is left out of the figure and named, never given a made-up value.
                        risk_factors = []
                        unrated: list[str] = []
                        for n in vuln_nodes_in_path:
                            prob = node_probability(n)
                            if prob is None:
                                unrated.append(n.cve_id)
                            else:
                                risk_factors.append(prob)

                        final_prob = None
                        if risk_factors:
                            total_risk = 1.0
                            for rf in risk_factors:
                                total_risk *= (1.0 - rf)
                            final_prob = round(1.0 - total_risk, 2)

                        summary_cves = " -> ".join([n.cve_id for n in vuln_nodes_in_path])
                        paths_found.append(AttackPath(
                            path_id=str(uuid4())[:8],
                            nodes=vuln_nodes_in_path,
                            total_risk_score=final_prob,
                            unrated_cves=unrated,
                            summary=f"Path exploits {summary_cves} to achieve {target.replace('_', ' ')}."
                        ))
                except Exception:
                    pass

        # Highest probability first; paths with no rated CVE last
        paths_found.sort(key=lambda p: (p.total_risk_score is not None, p.total_risk_score or 0.0), reverse=True)
        return paths_found


def node_probability(n: AttackChainNode) -> Optional[float]:
    """Exploitation probability of one CVE from the evidence it has; ``None`` when it has none.

    KEV = exploitation observed in the wild (0.99). Otherwise CVSS/10 blended 70/30 with EPSS when both are known; whichever
    one is known stands alone; neither known = ``None`` (the old code assumed a CVSS of 5.0 here).
    """
    if n.is_in_kev:
        return 0.99
    base = None if n.cvss_score is None else n.cvss_score / 10.0
    if base is None and n.epss_score is None:
        return None
    if base is None:
        return n.epss_score
    return base if n.epss_score is None else (base * 0.7) + (n.epss_score * 0.3)
