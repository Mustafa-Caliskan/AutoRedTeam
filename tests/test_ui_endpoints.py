"""
Tests for Phase 3: Web UI Human-in-the-Loop 2.0 and API Endpoints.
"""
import json
import threading
from assessment_ui import OperatorDecisionQueue, operator_queue


def test_operator_decision_queue_approve():
    """Verify operator queue correctly signals approval."""
    queue = OperatorDecisionQueue()
    
    def simulate_user_click():
        queue.submit_decision({"action": "approve"})
        
    t = threading.Thread(target=simulate_user_click)
    t.start()
    
    decision = queue.wait_for_decision(timeout=2.0)
    t.join()
    
    assert decision["action"] == "approve"


def test_operator_decision_queue_reject():
    """Verify operator queue correctly signals rejection."""
    queue = OperatorDecisionQueue()
    
    def simulate_user_reject():
        queue.submit_decision({"action": "reject", "reason": "unsafe port"})
        
    t = threading.Thread(target=simulate_user_reject)
    t.start()
    
    decision = queue.wait_for_decision(timeout=2.0)
    t.join()
    
    assert decision["action"] == "reject"
    assert decision["reason"] == "unsafe port"


def test_operator_decision_queue_timeout_fallback():
    """Verify queue falls back to automatic approval when operator does not answer within timeout."""
    queue = OperatorDecisionQueue()
    decision = queue.wait_for_decision(timeout=0.1)
    assert decision["action"] == "approve"
    assert decision.get("auto") is True


def test_api_docker_status_endpoint():
    """Verify /api/docker/status endpoint returns valid json health report."""
    from http.server import HTTPServer
    from assessment_ui import AssessmentUIHandler
    import urllib.request
    
    server = HTTPServer(('127.0.0.1', 0), AssessmentUIHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.handle_request)
    t.daemon = True
    t.start()
    
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/docker/status", timeout=5.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "docker_available" in data
            assert "containers" in data

    finally:
        server.server_close()


def test_api_llm_redteam_categories_endpoint():
    """Verify /api/llm_redteam/categories endpoint returns category list."""
    from http.server import HTTPServer
    from assessment_ui import AssessmentUIHandler
    import urllib.request
    
    server = HTTPServer(('127.0.0.1', 0), AssessmentUIHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.handle_request)
    t.daemon = True
    t.start()
    
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/llm_redteam/categories", timeout=5.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert isinstance(data, list)
            assert len(data) > 0
    finally:
        server.server_close()

