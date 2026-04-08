import logging
from pathlib import Path
import httpx

from hackersec.analysis.joern.exceptions import JoernConnectionError, JoernQueryError

logger = logging.getLogger(__name__)


class JoernClient:
    def __init__(self, base_url: str = "http://localhost:9000"):
        self.base_url = base_url.rstrip("/")
        # Joern endpoints often take significant processing time
        self.client = httpx.Client(timeout=300.0)

    def ping(self) -> bool:
        """Check if Joern Server is reachable."""
        try:
            # We fetch the query endpoint just to see if the HTTP port is open
            res = self.client.get(f"{self.base_url}/query/help", timeout=5.0)
            return res.status_code == 200
        except httpx.RequestError:
            return False

    def create_workspace(self, workspace_name: str) -> None:
        """Create a new workspace in Joern, overriding if it exists."""
        try:
            url = f"{self.base_url}/workspace/{workspace_name}"
            # Joern API convention: GET or POST depending on version, often POST is safer for creation
            # With Joern server standard API, we actually just use the query endpoint for most things.
            # However, standard workspace management might require explicit commands.
            # We'll execute a workspace creation command via the query API.
            query = f'workspace.create("{workspace_name}")'
            self._execute_raw(query)
        except httpx.RequestError as e:
            raise JoernConnectionError(f"Failed to reach Joern: {e}")

    def import_code(self, target_path: Path, workspace_name: str = "") -> None:
        """Import code into current/specified workspace."""
        try:
            # First set workspace if provided
            if workspace_name:
                self._execute_raw(f'workspace("{workspace_name}")')
            
            # Execute import command
            query = f'importCode("{target_path.absolute().as_posix()}")'
            res = self._execute_raw(query)
            if "Error" in res.get("response", ""):
                 raise JoernQueryError(f"Failed to import code: {res['response']}")
        except httpx.RequestError as e:
            raise JoernConnectionError(f"Failed to reach Joern during import: {e}")

    def _execute_raw(self, query: str) -> dict:
        """Send raw Scala query to Joern server."""
        payload = {"query": query}
        res = self.client.post(f"{self.base_url}/query", json=payload)
        res.raise_for_status()
        return res.json()

    def query_taint(self, workspace_name: str, file_name: str, line_num: int) -> dict:
        """
        Executes Scala query to find paths to the given sink line.
        """
        import json
        from hackersec.analysis.joern.queries import build_taint_query
        
        # Ensure we are in the right workspace
        if workspace_name:
             self._execute_raw(f'workspace("{workspace_name}")')
             
        query = build_taint_query(line_num)
        try:
            res = self._execute_raw(query)
            # Joern returns the requested toJson string output embedded in "response"
            output = res.get("response", "[]")
            
            # The Scala `toJson` might contain some Joern REPL framing.
            # Clean string around json array if necessary.
            output = output.strip()
            
            if not (output.startswith("[") and output.endswith("]")):
                if "No flows" in output or "empty" in output:
                    return {"cpg_status": "no_flow_found", "taint_paths": []}
                # Else it failed or returned weird string
                raise JoernQueryError(f"Unexpected Joern query output: {output[:100]}")
                
            flows = json.loads(output)
            if not flows:
                 return {"cpg_status": "no_flow_found", "taint_paths": []}
                 
            return {"cpg_status": "success", "taint_paths": flows}
            
        except (httpx.RequestError, json.JSONDecodeError) as e:
            raise JoernQueryError(f"Failed to query taint flow: {str(e)}")
