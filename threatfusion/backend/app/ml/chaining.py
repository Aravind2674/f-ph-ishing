"""
ThreatFusion – Predictive Vulnerability Chaining (Reasoning Engine)
==================================================================

This module implements the logical chainer that maps vulnerabilities to attack graphs:
1. Loads EPSS scores, CISA KEV status, and Exploit-DB ID mapping from the project root directory.
2. Queries the local Ollama instance (e.g. Llama-3) to determine vulnerability pre-conditions and post-conditions.
3. Builds a directed graph using networkx, weights edges based on CVSS/EPSS exploitability metrics, and calculates the attack paths.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from uuid import uuid4
import httpx
import networkx as nx
from typing import Optional, Any
from app.models.schemas import AttackChainNode, AttackPath, CVEDetail

logger = logging.getLogger(__name__)

# Path declarations (assuming datasets are in the project root)
BASE_DIR = Path(__file__).resolve().parents[4]
EPSS_PATH = BASE_DIR / "epss_scores-2026-07-12.csv"
KEV_PATH = BASE_DIR / "known_exploited_vulnerabilities.csv"
EXPLOITDB_PATH = BASE_DIR / "files_exploits.csv"
OLLAMA_API_URL = "http://localhost:11434/api/generate"


class VulnerabilityChainer:
    """The vulnerability chaining logic coordinator."""

    def __init__(self) -> None:
        self.epss_cache: dict[str, float] = {}
        self.kev_cache: set[str] = set()
        self.exploit_db_cache: dict[str, str] = {}
        self._initialized = False

    def initialize(self) -> None:
        """Parses the threat databases from disk into memory caches."""
        if self._initialized:
            return

        logger.info("Initializing Threat Catalog caches...")

        # 1. Parse EPSS CSV
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

        # 2. Parse CISA KEV CSV
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

        # 3. Parse Exploit-DB CSV
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

        self._initialized = True

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
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
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
            # Silent fallback if Ollama is not running or times out
            pass

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

    async def build_and_solve_chain(self, cves: list[CVEDetail]) -> list[AttackPath]:
        """Core chainer solving routing paths using NetworkX directed graph."""
        self.initialize()

        if not cves:
            return []

        # Hydrate raw NVD CVEs with local threat intelligence details
        hydrated_nodes: list[AttackChainNode] = []
        for cve in cves:
            cve_id = cve.cve_id.upper()
            epss = self.epss_cache.get(cve_id, 0.0)
            in_kev = cve_id in self.kev_cache
            exploit_db_id = self.exploit_db_cache.get(cve_id)
            
            pre_conds, post_conds = await self.get_pre_and_post_conditions(cve_id, cve.description)

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
                        
                        # Calculate path probability (Joint risk score)
                        # High CVSS / EPSS / KEV drops the edge weight, increasing probability
                        risk_factors = []
                        for n in vuln_nodes_in_path:
                            base_prob = (n.cvss_score or 5.0) / 10.0
                            if n.is_in_kev:
                                prob = 0.99
                            else:
                                # Blend CVSS and EPSS
                                prob = (base_prob * 0.7) + (n.epss_score * 0.3)
                            risk_factors.append(prob)
                            
                        # Joint risk: P(A union B union C...)
                        total_risk = 1.0
                        for rf in risk_factors:
                            total_risk *= (1.0 - rf)
                        final_prob = 1.0 - total_risk

                        summary_cves = " -> ".join([n.cve_id for n in vuln_nodes_in_path])
                        paths_found.append(AttackPath(
                            path_id=str(uuid4())[:8],
                            nodes=vuln_nodes_in_path,
                            total_risk_score=round(final_prob, 2),
                            summary=f"Path exploits {summary_cves} to achieve {target.replace('_', ' ')}."
                        ))
                except Exception:
                    pass

        # Sort by highest probability first
        paths_found.sort(key=lambda p: p.total_risk_score, reverse=True)
        return paths_found
