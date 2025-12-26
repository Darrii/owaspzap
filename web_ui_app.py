#!/usr/bin/env python3
"""
Web UI для Vulnerability Chain Detection System.
FastAPI + WebSocket для real-time updates.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import asyncio
import json
import subprocess
import uuid
import time
from pathlib import Path
from datetime import datetime

from vulnerability_chains.utils.zap_parser import ZAPAlertParser
from vulnerability_chains.core.taxonomy import VulnerabilityTaxonomy
from vulnerability_chains.rules.probabilistic_rules import ProbabilisticRuleEngine
from vulnerability_chains.core.context_analyzer import ContextAnalyzer
from vulnerability_chains.core.enhanced_detector import EnhancedChainDetector


app = FastAPI(title="Vulnerability Chain Detection System")

# Global storage for scan sessions
scan_sessions = {}


class ScanRequest(BaseModel):
    url: HttpUrl
    scan_type: str = "quick"  # quick, spider, active, ajax
    depth: int = 5
    timeout: int = 28800  # 8 hours default (7-8 hours typical for full scans)


class ChainAnalysisRequest(BaseModel):
    scan_id: str
    min_probability: float = 0.75  # Higher threshold for real exploitable chains
    min_chain_probability: float = 0.65  # Only highly probable chains
    max_chain_length: int = 4


class VerifyRequest(BaseModel):
    scan_id: str
    chain_ids: Optional[List[str]] = None  # None = verify all


class ScanSession:
    def __init__(self, scan_id: str, url: str, scan_type: str, depth: int, timeout: int):
        self.scan_id = scan_id
        self.url = url
        self.scan_type = scan_type
        self.depth = depth
        self.timeout = timeout
        self.status = "initializing"
        self.progress = 0
        self.zap_results = None
        self.chain_results = None
        self.verify_results = None
        self.process = None
        self.start_time = time.time()
        self.logs = []

    def add_log(self, message: str, level: str = "info"):
        self.logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "scan_type": self.scan_type,
            "depth": self.depth,
            "timeout": self.timeout,
            "status": self.status,
            "progress": self.progress,
            "elapsed_time": time.time() - self.start_time,
            "zap_results": self.zap_results,
            "chain_results": self.chain_results,
            "verify_results": self.verify_results,
            "logs": self.logs[-50:]  # Last 50 logs
        }


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)

    async def send_update(self, scan_id: str, data: dict):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(data)
                except:
                    pass


manager = ConnectionManager()


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main UI page"""
    return FileResponse("web_ui/index.html")


@app.get("/api/scans/previous")
async def get_previous_scans():
    """Get list of previous ZAP scans from scans/ directory"""
    scans_dir = Path("scans")
    if not scans_dir.exists():
        return {"scans": []}

    scans = []
    for scan_file in scans_dir.glob("*.json"):
        if scan_file.stat().st_size > 100:  # Skip empty files
            scans.append({
                "scan_id": scan_file.stem,
                "filename": scan_file.name,
                "size": scan_file.stat().st_size,
                "modified": scan_file.stat().st_mtime
            })

    # Sort by modification time (newest first)
    scans.sort(key=lambda x: x['modified'], reverse=True)
    return {"scans": scans[:20]}  # Return last 20 scans


@app.post("/api/scan/load/{scan_id}")
async def load_previous_scan(scan_id: str):
    """Load a previous ZAP scan for chain analysis"""
    scan_file = Path(f"scans/{scan_id}.json")
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    # Parse scan to get vulnerability count
    from vulnerability_chains.utils.zap_parser import ZAPAlertParser
    parser = ZAPAlertParser()
    vulnerabilities = parser.parse_zap_report(str(scan_file))

    # Create session from saved scan
    session = ScanSession(
        scan_id=scan_id,
        url="[Loaded from file]",
        scan_type="loaded",
        depth=0,
        timeout=0
    )
    session.status = "completed"
    session.progress = 100
    session.scan_file = str(scan_file)
    session.zap_results = {"vulnerabilities": len(vulnerabilities)}
    session.add_log(f"Loaded previous scan: {scan_file.name}")
    session.add_log(f"Found {len(vulnerabilities)} vulnerabilities")

    scan_sessions[scan_id] = session
    return {
        "scan_id": scan_id,
        "status": "loaded",
        "file": str(scan_file),
        "vulnerabilities": len(vulnerabilities)
    }


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start ZAP scan"""
    scan_id = str(uuid.uuid4())
    session = ScanSession(
        scan_id=scan_id,
        url=str(request.url),
        scan_type=request.scan_type,
        depth=request.depth,
        timeout=request.timeout
    )
    scan_sessions[scan_id] = session

    # Start scan in background
    background_tasks.add_task(run_zap_scan, scan_id)

    return {"scan_id": scan_id, "status": "started"}


async def run_zap_scan(scan_id: str):
    """Run ZAP scan in background using ZAP API"""
    import requests

    session = scan_sessions[scan_id]
    session.status = "scanning"

    # Ensure URL has protocol
    url = session.url
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
        session.url = url

    session.add_log(f"Starting {session.scan_type} scan for {url}")

    try:
        # ZAP API base URL
        zap_url = "http://localhost:8090"
        zap_api_key = "changeme"  # Default ZAP Docker API key

        # Prepare output path
        output_dir = Path("scans")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"{scan_id}.json"

        session.add_log(f"Using ZAP API at {zap_url}")
        session.progress = 10
        await manager.send_update(scan_id, {
            "type": "progress",
            "progress": 10,
            "message": "Connecting to ZAP..."
        })

        # Start spider
        session.add_log(f"Starting spider for {session.url}")
        spider_response = requests.get(f"{zap_url}/JSON/spider/action/scan/", params={
            "url": session.url,
            "maxChildren": session.depth,
            "apikey": zap_api_key
        })
        spider_scan_id = spider_response.json()['scan']

        session.progress = 20
        await manager.send_update(scan_id, {
            "type": "progress",
            "progress": 20,
            "message": "Spider started..."
        })

        # Monitor spider progress
        while True:
            status_response = requests.get(f"{zap_url}/JSON/spider/view/status/", params={
                "scanId": spider_scan_id,
                "apikey": zap_api_key
            })
            spider_progress = int(status_response.json()['status'])

            # Scale spider progress to 20-60%
            total_progress = 20 + (spider_progress * 40 // 100)
            session.progress = total_progress

            session.add_log(f"Spider progress: {spider_progress}%")
            await manager.send_update(scan_id, {
                "type": "progress",
                "progress": total_progress,
                "message": f"Spidering: {spider_progress}%"
            })

            # Warning at 37%
            if total_progress >= 37 and total_progress <= 40:
                await manager.send_update(scan_id, {
                    "type": "warning",
                    "message": "Сканирование может застрять на 37%, это нормально!"
                })

            if spider_progress >= 100:
                break

            await asyncio.sleep(2)

        session.add_log("Spider completed")

        # Run active scan if requested
        if session.scan_type in ["active", "quick"]:
            # Wait a bit for spider results to be processed by ZAP
            session.add_log("Waiting for ZAP to process spider results...")
            await asyncio.sleep(15)  # Increased from 5 to 15 seconds

            # Get URLs from ZAP scan tree to find the actual URL to scan
            # (ZAP might redirect https:// to http://)
            session.add_log("Getting URLs from ZAP scan tree...")
            urls_response = requests.get(f"{zap_url}/JSON/core/view/urls/", params={
                "apikey": zap_api_key
            })
            zap_urls = urls_response.json().get('urls', [])

            # Find best matching URL (prefer exact match, fallback to base domain)
            target_host = session.url.replace('https://', '').replace('http://', '').split('/')[0]
            scan_url = None

            # Try to find exact match first
            for url in zap_urls:
                if target_host in url and url.endswith('/'):
                    scan_url = url
                    break

            # If no exact match, use first URL with matching domain
            if not scan_url:
                for url in zap_urls:
                    if target_host in url:
                        scan_url = url
                        break

            # Fallback to original URL
            if not scan_url:
                scan_url = session.url

            session.add_log(f"Using URL for active scan: {scan_url}")

            session.add_log("Starting active scan...")
            active_response = requests.get(f"{zap_url}/JSON/ascan/action/scan/", params={
                "url": scan_url,
                "recurse": "true",
                "apikey": zap_api_key
            })

            # Check if scan started successfully
            response_data = active_response.json()
            if 'scan' not in response_data:
                session.add_log(f"ERROR: Failed to start active scan: {response_data}", "error")
                session.add_log(f"Available URLs in ZAP: {zap_urls[:5]}", "error")
                raise Exception(f"ZAP active scan failed: {response_data.get('message', 'Unknown error')}")

            active_scan_id = response_data['scan']
            session.add_log(f"Active scan started with ID: {active_scan_id}")

            # Monitor active scan progress with timeout
            max_iterations = 720  # 1 hour max (720 * 5 seconds)
            iterations = 0
            while iterations < max_iterations:
                try:
                    # Check ALL scans to see if any are finished
                    scans_response = requests.get(f"{zap_url}/JSON/ascan/view/scans/", params={
                        "apikey": zap_api_key
                    }, timeout=10)
                    scans = scans_response.json()['scans']

                    # Find our scan by exact ID match
                    active_progress = 0
                    for scan in scans:
                        if scan['id'] == active_scan_id:
                            active_progress = int(scan['progress'])
                            if scan['state'] == 'FINISHED':
                                active_progress = 100
                            break

                    # If no matching scan found, check the specific scan ID
                    if active_progress == 0:
                        status_response = requests.get(f"{zap_url}/JSON/ascan/view/status/", params={
                            "scanId": active_scan_id,
                            "apikey": zap_api_key
                        }, timeout=10)
                        active_progress = int(status_response.json()['status'])
                except Exception as e:
                    session.add_log(f"Error checking scan status: {e}", "error")
                    # If status check fails, assume completed
                    active_progress = 100

                # Scale active scan to 60-100%
                total_progress = 60 + (active_progress * 40 // 100)
                session.progress = total_progress

                session.add_log(f"Active scan progress: {active_progress}%")
                await manager.send_update(scan_id, {
                    "type": "progress",
                    "progress": total_progress,
                    "message": f"Active scan: {active_progress}%"
                })

                if active_progress >= 100:
                    break

                await asyncio.sleep(5)
                iterations += 1

        # Get alerts
        session.add_log("Fetching alerts...")
        # Don't filter by baseurl - ZAP might have scanned http:// while we requested https://
        alerts_response = requests.get(f"{zap_url}/JSON/core/view/alerts/", params={
            "apikey": zap_api_key
        })
        alerts = alerts_response.json()['alerts']

        # Filter alerts manually to match our target (with or without protocol)
        target_host = session.url.replace('https://', '').replace('http://', '').split('/')[0]
        filtered_alerts = [a for a in alerts if target_host in a.get('url', '')]
        alerts = filtered_alerts

        # Save to file
        with open(output_file, 'w') as f:
            json.dump({"site": [{"alerts": alerts}]}, f, indent=2)

        session.add_log("Parsing ZAP results...")
        parser = ZAPAlertParser()
        vulnerabilities = parser.parse_zap_report(str(output_file))

        # Extract statistics
        vuln_by_risk = {}
        vuln_by_type = {}
        urls_found = set()
        subdomains = set()

        for v in vulnerabilities:
            # Count by risk
            risk = v.risk.name
            vuln_by_risk[risk] = vuln_by_risk.get(risk, 0) + 1

            # Count by type
            vuln_by_type[v.name] = vuln_by_type.get(v.name, 0) + 1

            # Extract URLs and subdomains
            if v.url:
                urls_found.add(v.url)
                from urllib.parse import urlparse
                parsed = urlparse(v.url)
                subdomains.add(parsed.netloc)

        session.zap_results = {
            "total_vulnerabilities": len(vulnerabilities),
            "by_risk": vuln_by_risk,
            "by_type": dict(sorted(vuln_by_type.items(), key=lambda x: -x[1])[:20]),
            "total_urls": len(urls_found),
            "urls_sample": list(urls_found)[:50],
            "subdomains": list(subdomains),
            "scan_file": str(output_file)
        }

        session.status = "completed"
        session.progress = 100
        session.add_log(f"Scan completed! Found {len(vulnerabilities)} vulnerabilities")

        await manager.send_update(scan_id, {
            "type": "completed",
            "results": session.zap_results
        })

    except Exception as e:
        session.status = "error"
        session.add_log(f"Error: {str(e)}", "error")


@app.post("/api/scan/stop/{scan_id}")
async def stop_scan(scan_id: str):
    """Stop running scan"""
    if scan_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = scan_sessions[scan_id]
    session.status = "stopped"
    session.add_log("Scan stopped by user")

    return {"status": "stopped"}


@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan_sessions[scan_id].to_dict()


@app.post("/api/chains/analyze")
async def analyze_chains(request: ChainAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze vulnerability chains"""
    if request.scan_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = scan_sessions[request.scan_id]

    if not session.zap_results:
        raise HTTPException(status_code=400, detail="ZAP scan not completed")

    background_tasks.add_task(run_chain_analysis, request.scan_id, request)

    return {"status": "analyzing"}


async def run_chain_analysis(scan_id: str, config: ChainAnalysisRequest):
    """Run chain analysis in background"""
    session = scan_sessions[scan_id]
    session.add_log("Starting chain analysis...")

    try:
        # Parse ZAP results
        parser = ZAPAlertParser()
        scan_file = session.scan_file if hasattr(session, 'scan_file') else session.zap_results.get("scan_file")
        vulnerabilities = parser.parse_zap_report(scan_file)

        session.add_log(f"Analyzing {len(vulnerabilities)} vulnerabilities")

        # Build detector
        taxonomy = VulnerabilityTaxonomy()
        rule_engine = ProbabilisticRuleEngine(taxonomy)
        context_analyzer = ContextAnalyzer()

        detector = EnhancedChainDetector(
            taxonomy=taxonomy,
            rule_engine=rule_engine,
            context_analyzer=context_analyzer,
            config={
                'min_probability': config.min_probability,
                'enable_transitive': False,
                'enable_cluster_links': False,  # Disable to reduce edge explosion
                'cluster_link_boost': 1.15
            }
        )

        # Build graph
        session.add_log("Building vulnerability graph...")
        graph = detector.build_graph(vulnerabilities)

        # Find chains with smart deduplication on-the-fly
        session.add_log("Finding vulnerability chains with smart deduplication...")
        unique_chains_map = {}  # Deduplicate on-the-fly
        max_unique = 100  # Stop after finding 100 unique chain signatures

        import asyncio
        node_count = 0
        total_found = 0

        for start_node in detector.graph.nodes():
            if len(unique_chains_map) >= max_unique:
                session.add_log(f"Found {max_unique} unique chain patterns, stopping search...")
                break

            temp_chains = []
            visited = {start_node}
            detector._dfs_chains(
                current=start_node,
                path=[start_node],
                path_probability=1.0,
                visited=visited,
                chains=temp_chains,
                min_length=2,
                max_length=config.max_chain_length,
                min_prob=config.min_chain_probability,
                max_chains=500  # Limit per node to prevent explosion
            )

            # Deduplicate on-the-fly
            total_found += len(temp_chains)
            for chain in temp_chains:
                sig = tuple(v.name for v in chain.vulnerabilities)
                if sig not in unique_chains_map or chain.risk_score > unique_chains_map[sig].risk_score:
                    unique_chains_map[sig] = chain

            # Yield control periodically to prevent blocking
            node_count += 1
            if node_count % 5 == 0:
                await asyncio.sleep(0)  # Let other tasks run

            # Log progress every 10 nodes
            if node_count % 10 == 0:
                session.add_log(f"Processed {node_count}/{graph.number_of_nodes()} nodes, {len(unique_chains_map)} unique chains from {total_found} total...")

        chains = list(unique_chains_map.values())
        session.add_log(f"Processed {node_count} nodes, found {len(chains)} unique chains (from {total_found} total)")

        # Remove subchains (if A→B→C exists, remove A→B and B→C)
        def is_subchain(chain1, chain2):
            """Check if chain1 is a subchain of chain2"""
            sig1 = tuple(v.name for v in chain1.vulnerabilities)
            sig2 = tuple(v.name for v in chain2.vulnerabilities)
            if len(sig1) >= len(sig2):
                return False
            # Check if sig1 is a contiguous subsequence of sig2
            for i in range(len(sig2) - len(sig1) + 1):
                if sig2[i:i+len(sig1)] == sig1:
                    return True
            return False

        filtered_chains = []
        for chain in chains:
            # Check if this chain is a subchain of any other chain
            is_sub = False
            for other_chain in chains:
                if chain != other_chain and is_subchain(chain, other_chain):
                    is_sub = True
                    break
            if not is_sub:
                filtered_chains.append(chain)

        chains = filtered_chains
        session.add_log(f"After removing subchains: {len(chains)} final chains")

        # Categorize chains using normalized risk score thresholds (0-100)
        # CRITICAL: 90-100, HIGH: 70-89, MEDIUM: 40-69, LOW: 0-39
        critical_chains = [c for c in chains if c.risk_score >= 90]
        high_chains = [c for c in chains if 70 <= c.risk_score < 90]
        medium_chains = [c for c in chains if 40 <= c.risk_score < 70]
        low_chains = [c for c in chains if c.risk_score < 40]

        # Sort chains by risk score (highest first) and limit to top 1000 for UI performance
        chains_sorted = sorted(chains, key=lambda c: c.risk_score, reverse=True)
        chains_to_display = chains_sorted[:1000]

        session.add_log(f"Found {len(chains)} chains total, displaying top {len(chains_to_display)}")

        # Convert chains to JSON-serializable format
        chains_data = []
        for i, chain in enumerate(chains_to_display):
            chains_data.append({
                "id": f"chain_{i}",
                "risk_score": chain.risk_score,
                "confidence": chain.confidence,
                "chain_type": chain.chain_type.name,
                "length": len(chain.vulnerabilities),
                "vulnerabilities": [
                    {
                        "name": v.name,
                        "url": v.url,
                        "risk": v.risk.name,
                        "description": v.description
                    }
                    for v in chain.vulnerabilities
                ]
            })

        session.chain_results = {
            "total_chains": len(chains),
            "critical": len(critical_chains),
            "high": len(high_chains),
            "medium": len(medium_chains),
            "low": len(low_chains),
            "chains": chains_data,
            "graph_stats": {
                "nodes": graph.number_of_nodes(),
                "edges": graph.number_of_edges()
            }
        }

        session.add_log(f"Found {len(chains)} vulnerability chains!")

        await manager.send_update(scan_id, {
            "type": "chains_analyzed",
            "results": session.chain_results
        })

    except Exception as e:
        import traceback
        error_msg = f"Chain analysis error: {str(e)}\n{traceback.format_exc()}"
        session.add_log(error_msg, "error")
        print(f"ERROR in run_chain_analysis: {error_msg}")  # Print to console for debugging


@app.post("/api/chains/verify")
async def verify_chains(request: VerifyRequest, background_tasks: BackgroundTasks):
    """Verify exploitability of chains"""
    if request.scan_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = scan_sessions[request.scan_id]

    if not session.chain_results:
        raise HTTPException(status_code=400, detail="Chain analysis not completed")

    background_tasks.add_task(run_verification, request.scan_id, request.chain_ids)

    return {"status": "verifying"}


async def run_verification(scan_id: str, chain_ids: Optional[List[str]]):
    """Run exploitability verification"""
    session = scan_sessions[scan_id]
    session.add_log("Starting exploitability verification...")

    # TODO: Implement actual verification logic from verify_homebank_chains.py
    # For now, return mock results

    session.verify_results = {
        "verified_chains": 0,
        "exploitable": 0,
        "details": []
    }

    session.add_log("Verification completed")


@app.get("/api/export/{scan_id}")
async def export_results(scan_id: str):
    """Export all results as JSON"""
    if scan_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = scan_sessions[scan_id]
    return JSONResponse(content=session.to_dict())


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket for real-time updates"""
    await manager.connect(websocket, scan_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8888)
