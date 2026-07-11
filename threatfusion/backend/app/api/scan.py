"""
ThreatFusion – Scan API Endpoints
=================================

Handles IOC submission, fan-out enrichment, ML scoring, and history retrieval.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from app.ingestion.cve import CVEClient
from app.ingestion.shodan import ShodanClient
from app.ingestion.techfingerprint import TechFingerprintClient
from app.ingestion.virustotal import VirusTotalClient
from app.ml.baseline import baseline_score
from app.ml.explain import explain_prediction
from app.ml.features import extract_features
from app.ml.fusion_model import FusionModel
from app.models.schemas import (
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanResult,
    TargetType,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

# ── In-Memory Database ──────────────────────────────────────────────────
# For the scope of this university project demo, we use an in-memory dict
# to persist scan results. In a real environment, this would be SQLite/Postgres.
_db: dict[str, ScanResult] = {}

# ── ML Model Initialization ─────────────────────────────────────────────
_model = FusionModel()
# Attempt to load model (handles being run from project root or backend dir)
_possible_paths = [
    Path("ml/models/fusion_model.json"),
    Path("../ml/models/fusion_model.json")
]
for p in _possible_paths:
    if p.exists():
        _model.load(p)
        break


def _get_ml_label(score: float) -> str:
    """Map a continuous probability [0, 1] to a qualitative label."""
    if score < 0.25:
        return "Low"
    if score < 0.50:
        return "Medium"
    if score < 0.75:
        return "High"
    return "Critical"


# ── Endpoints ───────────────────────────────────────────────────────────

@router.post("", response_model=ScanResponse, summary="Submit a new IOC scan")
async def create_scan(request: ScanRequest) -> ScanResponse:
    """Accept an IOC and run the full enrichment and ML scoring pipeline.
    
    This endpoint executes synchronously for demonstration purposes.
    """
    scan_id = str(uuid4())
    logger.info("Starting scan %s for %s (%s)", scan_id, request.target, request.target_type)
    
    # Data source placeholders
    vt = None
    shodan = None
    cve = None
    tech = None
    
    sources_succeeded = []
    sources_failed = []
    
    # Pull configuration
    from app.core.config import get_settings
    settings = get_settings()
    use_mock = settings.USE_MOCK_DATA
    
    vt_client = VirusTotalClient(api_key=settings.VIRUSTOTAL_API_KEY, use_mock=use_mock)
    shodan_client = ShodanClient(api_key=settings.SHODAN_API_KEY, use_mock=use_mock)
    cve_client = CVEClient(api_key=settings.NVD_API_KEY, use_mock=use_mock)
    tech_client = TechFingerprintClient(use_mock=use_mock)
    
    try:
        # ── 1. Data Enrichment (Sequential for rate-limit safety) ───────
        
        # VirusTotal
        try:
            if request.target_type == TargetType.DOMAIN:
                vt = await vt_client.lookup_domain(request.target)
            elif request.target_type == TargetType.IP:
                vt = await vt_client.lookup_domain(request.target) # Mock VT handles IP as domain
            elif request.target_type == TargetType.URL:
                vt = await vt_client.lookup_url(request.target)
            elif request.target_type == TargetType.FILE_HASH:
                vt = await vt_client.lookup_file_hash(request.target)
            
            if vt:
                sources_succeeded.append("VirusTotal")
        except Exception as e:
            logger.warning("VirusTotal lookup failed: %s", e)
            sources_failed.append("VirusTotal")

        # Shodan (Only relevant for IPs and Domains)
        if request.target_type in (TargetType.IP, TargetType.DOMAIN):
            try:
                ip_target = request.target
                if request.target_type == TargetType.DOMAIN:
                    import socket
                    from urllib.parse import urlparse
                    
                    clean_target = request.target.strip()
                    if clean_target.startswith("http://") or clean_target.startswith("https://"):
                        parsed = urlparse(clean_target)
                        clean_target = parsed.netloc or parsed.path
                    clean_target = clean_target.split('/')[0]
                    
                    ip_target = socket.gethostbyname(clean_target)
                
                # In mock mode, lookup_ip handles both
                shodan = await shodan_client.lookup_ip(ip_target)
                if shodan:
                    sources_succeeded.append("Shodan")
            except Exception as e:
                logger.warning("Shodan lookup failed: %s", e)
                sources_failed.append("Shodan")

        # NVD / CVE (Triggers if Shodan found vulnerabilities)
        if shodan and shodan.vulns:
            try:
                cve = await cve_client.lookup_cves(shodan.vulns)
                if cve:
                    sources_succeeded.append("NVD")
            except Exception as e:
                logger.warning("CVE lookup failed: %s", e)
                sources_failed.append("NVD")

        # Technology Fingerprinting (Only relevant for URLs/Domains)
        if request.target_type in (TargetType.URL, TargetType.DOMAIN):
            try:
                target_url = request.target
                if not target_url.startswith("http"):
                    target_url = f"https://{target_url}"
                tech = await tech_client.fingerprint_url(target_url)
                if tech:
                    sources_succeeded.append("TechFingerprint")
            except Exception as e:
                logger.warning("Tech fingerprinting failed: %s", e)
                sources_failed.append("TechFingerprint")

        # ── 2. Feature Engineering ──────────────────────────────────────
        features = extract_features(vt, shodan, cve, tech)
        
        # ── 3. Rule-Based Baseline ──────────────────────────────────────
        b_score = baseline_score(features)
        
        # ── 4. ML Fusion Model & SHAP ───────────────────────────────────
        m_score = None
        m_label = None
        explanations = []
        
        if _model.is_loaded:
            m_score = _model.predict_proba(features)
            m_label = _get_ml_label(m_score)
            explanations = explain_prediction(_model, features)
        else:
            logger.warning("ML Model not loaded. Using baseline score only.")
            m_score = b_score
            m_label = _get_ml_label(b_score)

        # ── 5. Generate Plain-Language Summary ──────────────────────────
        summary_parts = []
        if m_label in ("Critical", "High"):
            summary_parts.append(f"This target presents a {m_label.lower()} risk profile.")
        else:
            summary_parts.append(f"This target presents a {m_label.lower()} risk profile.")
            
        if vt and vt.malicious_count > 0:
            summary_parts.append(f"It is flagged by {vt.malicious_count} AV engines.")
        elif vt:
            summary_parts.append("It is generally trusted by security vendors.")
            
        if shodan and shodan.open_ports:
            summary_parts.append(f"There are {len(shodan.open_ports)} exposed ports, ")
            if cve and cve.cves:
                summary_parts.append(f"with {len(cve.cves)} known CVEs detected.")
            else:
                summary_parts.append("with no critical CVEs immediately apparent.")
                
        summary_text = " ".join(summary_parts)

        # Assemble the final payload
        result = ScanResult(
            scan_id=scan_id,
            target=request.target,
            target_type=request.target_type,
            timestamp=datetime.now(timezone.utc),
            virustotal=vt,
            shodan=shodan,
            cve=cve,
            tech_fingerprint=tech,
            features=features,
            baseline_score=b_score,
            ml_score=m_score,
            ml_label=m_label,
            explanations=explanations,
            summary=summary_text,
            data_sources_succeeded=sources_succeeded,
            data_sources_failed=sources_failed,
            mock_mode=use_mock
        )
        
        # Persist to "database"
        _db[scan_id] = result
        
        return ScanResponse(success=True, result=result, error=None)
        
    except Exception as e:
        logger.exception("Critical error during scan processing.")
        return ScanResponse(success=False, result=None, error=str(e))
        
    finally:
        # Ensure all async clients are closed
        await vt_client.close()
        await shodan_client.close()
        await cve_client.close()
        await tech_client.close()


@router.get("/history", response_model=list[ScanHistoryItem], summary="List scan history")
async def get_history() -> list[ScanHistoryItem]:
    """Retrieve all past scans, sorted by newest first."""
    history = []
    # Sort descending by timestamp
    sorted_scans = sorted(_db.values(), key=lambda r: r.timestamp, reverse=True)
    
    for res in sorted_scans:
        history.append(ScanHistoryItem(
            scan_id=res.scan_id,
            target=res.target,
            target_type=res.target_type,
            timestamp=res.timestamp,
            baseline_score=res.baseline_score,
            ml_score=res.ml_score,
            ml_label=res.ml_label
        ))
    return history


@router.get("/{scan_id}", response_model=ScanResponse, summary="Retrieve a specific scan")
async def get_scan(scan_id: str) -> ScanResponse:
    """Fetch the full enrichment payload and ML risk score for a single scan."""
    if scan_id not in _db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found."
        )
    return ScanResponse(success=True, result=_db[scan_id], error=None)
