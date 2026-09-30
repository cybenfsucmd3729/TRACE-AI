"""
TRACE-AI: AI-Powered Digital Evidence Correlation & Forensic Investigation Framework
Developed for SUTRAM 2026 National Level Cyber Hackathon
Organized by IGDTUW under ISEA Project Phase-III, MeitY, Govt. of India
"""

import os
import json
import time
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel

from forensic_engine.ingestion import EvidenceIngester
from forensic_engine.parsers import ForensicParserManager
from forensic_engine.correlation import CorrelationEngine
from forensic_engine.graph_engine import ForensicGraphEngine
from forensic_engine.sec65b_generator import Sec65BCertificateGenerator
from ai_copilot.grounded_rag import GroundedAICopilot


app = FastAPI(
    title="TRACE-AI Forensic Framework",
    description="AI-Powered Digital Evidence Correlation & Legal Admissibility Framework (BSA 2023 / Sec 65B)",
    version="1.0.0"
)


# Initialize Core Services
ingester = EvidenceIngester()
parser_manager = ForensicParserManager()
correlation_engine = CorrelationEngine()
graph_engine = ForensicGraphEngine()
sec65b_generator = Sec65BCertificateGenerator()
copilot = GroundedAICopilot()


# Mount Static Files
static_dir = os.path.join(os.path.dirname(__file__), "static")

if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def read_root():
    index_path = os.path.join(static_dir, "index.html")

    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    return HTMLResponse(content="<h1>TRACE-AI API Server Running</h1>")


@app.get("/api/health")
async def health_check():
    return {
        "status": "ONLINE",
        "system": "TRACE-AI v1.0.0 (SUTRAM 2026 Edition)",
        "compliance": "Bharatiya Sakshya Adhiniyam 2023 / Sec 65B Compliant",
        "meity_isea_phase": "ISEA Phase-III (IGDTUW)"
    }


@app.post("/api/evidence/upload")
async def upload_evidence(
    file: UploadFile = File(...),
    investigator: str = Form("Officer Admin")
):
    """
    Step 1: Cryptographic Ingestion & Evidence Lock
    Computes SHA-256, SHA-3, logs Chain of Custody entry.
    """
    try:
        content = await file.read()

        evidence_record = ingester.process_file(
            file.filename,
            content,
            investigator
        )

        parsed_events = parser_manager.parse_file(
            file.filename,
            content,
            evidence_record["evidence_id"]
        )

        correlation_engine.add_events(parsed_events)

        return {
            "status": "SUCCESS",
            "message": f"Artifact {file.filename} ingested and cryptographically locked.",
            "evidence": evidence_record,
            "parsed_event_count": len(parsed_events)
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/evidence/chain-of-custody")
async def get_chain_of_custody():
    """Returns the immutable Chain of Custody audit ledger."""
    return {
        "chain_of_custody": ingester.get_ledger(),
        "total_records": len(ingester.get_ledger())
    }


@app.get("/api/evidence/list")
async def get_evidence_list():
    """Returns list of all cryptographically locked evidence files."""
    return {
        "files": ingester.get_evidence_files(),
        "total_files": len(ingester.get_evidence_files())
    }


@app.get("/api/forensics/demo-scenario")
async def load_demo_scenario():
    """
    Loads the SUTRAM 2026 Master Attack Demo Scenario:
    1. USB Device Attached (Kingston 32GB)
    2. File Exfiltration (confidential_q3.xlsx to E:)
    3. Obfuscated PowerShell Execution (Base64 flag)
    4. DNS C2 Beaconing to malicious domain
    """
    demo_data = correlation_engine.load_demo_scenario()
    graph_data = graph_engine.build_graph(demo_data["events"])
    mitre_data = correlation_engine.get_mitre_matrix(demo_data["events"])

    return {
        "status": "SUCCESS",
        "scenario": demo_data,
        "causal_graph": graph_data,
        "mitre_matrix": mitre_data,
        "summary": demo_data["summary"]
    }


@app.get("/api/forensics/timeline")
async def get_timeline():
    """Returns microsecond-synchronized timeline swimlanes."""
    timeline = correlation_engine.get_unified_timeline()

    return {
        "timeline": timeline,
        "event_count": len(timeline)
    }


@app.get("/api/forensics/graph")
async def get_causal_graph():
    """Returns the visual node-link causal event graph."""
    events = correlation_engine.get_unified_timeline()
    graph_data = graph_engine.build_graph(events)

    return graph_data


@app.get("/api/forensics/mitre-matrix")
async def get_mitre_mapping():
    """Returns mapping of evidence to MITRE ATT&CK tactics & techniques."""
    events = correlation_engine.get_unified_timeline()

    return correlation_engine.get_mitre_matrix(events)


class CopilotQuery(BaseModel):
    query: str
    session_id: Optional[str] = "default"


@app.post("/api/copilot/query")
async def query_copilot(request: CopilotQuery):
    """
    Step 3: Zero-Hallucination Grounded AI Copilot Query
    Answers investigator questions strictly using verified event logs and timestamps.
    """
    events = correlation_engine.get_unified_timeline()
    response = copilot.analyze(request.query, events)

    return response


@app.post("/api/legal/generate-sec65b")
async def generate_sec65b_certificate(
    investigator_name: str = Form("Inspector V. Sharma"),
    agency: str = Form("Cyber Crime Cell, Delhi Police"),
    case_reference: str = Form("FIR-2026/0492-SUTRAM"),
    device_details: str = Form("Forensic Workstation RIG-01 (Ubuntu 24.04 LTS)")
):
    """
    Step 4: Bharatiya Sakshya Adhiniyam (BSA 2023) / Sec 65B Certificate Generation
    Outputs legally certified electronic evidence document with SHA-256 hashes & tamper-evident signature.
    """
    events = correlation_engine.get_unified_timeline()
    ledger = ingester.get_ledger()

    cert = sec65b_generator.generate_certificate(
        investigator_name=investigator_name,
        agency=agency,
        case_reference=case_reference,
        device_details=device_details,
        evidence_ledger=ledger,
        timeline_events=events
    )

    return cert


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
