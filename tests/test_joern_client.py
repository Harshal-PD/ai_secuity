import pytest
from unittest.mock import patch, MagicMock
from hackersec.analysis.joern.client import JoernClient
from hackersec.analysis.joern.exceptions import JoernConnectionError, JoernQueryError


def test_joern_client_ping_success():
    client = JoernClient(base_url="http://fake-joern:9000")
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value.status_code = 200
        assert client.ping() is True


def test_joern_client_ping_failure():
    import httpx
    client = JoernClient(base_url="http://fake-joern:9000")
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = httpx.RequestError("Failed")
        assert client.ping() is False


def test_query_taint_graceful_no_flow():
    client = JoernClient()
    with patch.object(client, "_execute_raw") as mock_exec:
        # Simulate Joern "No flows" response
        mock_exec.return_value = {"response": "No flows found."}
        
        result = client.query_taint("test_workspace", "app.py", 10)
        assert result["cpg_status"] == "no_flow_found"
        assert result["taint_paths"] == []


def test_query_taint_success_flow():
    client = JoernClient()
    with patch.object(client, "_execute_raw") as mock_exec:
        # Simulate Joern successful JSON response
        mock_exec.return_value = {
            "response": """[
                [{"line": 5, "code": "source"}, {"line": 10, "code": "sink"}]
            ]"""
        }
        
        result = client.query_taint("test_workspace", "app.py", 10)
        assert result["cpg_status"] == "success"
        assert len(result["taint_paths"]) == 1
        assert result["taint_paths"][0][1]["line"] == 10
