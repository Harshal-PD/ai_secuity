import json
import logging
import os
import re
import time
from pathlib import Path

import httpx

from hackersec.analysis.joern.exceptions import JoernConnectionError, JoernQueryError
from hackersec.analysis.joern.queries import (
    IMPORT_BEGIN,
    IMPORT_END,
    TAINT_BEGIN,
    TAINT_END,
    build_delete_query,
    build_import_query,
    build_taint_query,
)

logger = logging.getLogger(__name__)

_DEFAULT_JOERN_URL = os.getenv("JOERN_BASE_URL", "http://localhost:9000")
_QUERY_TIMEOUT = float(os.getenv("JOERN_QUERY_TIMEOUT", "600"))
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TRIPLE = re.compile(r'"""(.*?)"""', re.S)
_ESCAPED = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def _value_text(stdout: str, marker: str) -> str:
    """
    The REPL renders a String result either raw inside triple quotes or as an
    escaped literal. Return the decoded string that carries `marker`, or the
    raw output when neither form is present.
    """
    for m in _TRIPLE.finditer(stdout):
        if marker in m.group(1):
            return m.group(1)
    for m in _ESCAPED.finditer(stdout):
        if marker in m.group(1):
            try:
                return json.loads('"' + m.group(1) + '"')
            except json.JSONDecodeError:
                return m.group(1).replace('\\"', '"').replace("\\\\", "\\")
    return stdout


def _between(text: str, begin: str, end: str) -> str | None:
    start = text.find(begin)
    if start == -1:
        return None
    stop = text.find(end, start + len(begin))
    if stop == -1:
        return None
    return text[start + len(begin):stop]


class JoernClient:
    def __init__(self, base_url: str = _DEFAULT_JOERN_URL):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=_QUERY_TIMEOUT)
        self._sync_endpoint = True

    def ping(self) -> bool:
        """Check if Joern Server is reachable (any HTTP answer counts)."""
        try:
            res = self.client.get(self.base_url, timeout=5.0)
            return res.status_code < 500
        except httpx.RequestError:
            return False

    def ready(self) -> bool:
        """True once the server can actually evaluate a query."""
        try:
            out = self._execute_raw('"<<HS_" + "OK>>"')
        except (httpx.HTTPError, JoernQueryError):
            return False
        return "<<HS_OK>>" in (out.get("stdout") or "")

    # ── Transport ───────────────────────────────────────────────────────────

    def _execute_raw(self, query: str) -> dict:
        """
        Run a Scala query and wait for its output.

        `/query` only enqueues work and returns a UUID, so reading it directly
        yields nothing. `/query-sync` blocks until the result is ready; older
        servers without it are polled through `/result/<uuid>`.
        """
        payload = {"query": query}
        if self._sync_endpoint:
            res = self.client.post(f"{self.base_url}/query-sync", json=payload)
            if res.status_code == 404:
                self._sync_endpoint = False
            else:
                res.raise_for_status()
                return self._normalize(res.json())

        res = self.client.post(f"{self.base_url}/query", json=payload)
        res.raise_for_status()
        uuid = res.json().get("uuid")
        if not uuid:
            raise JoernQueryError(f"Joern did not accept the query: {res.text[:200]}")
        deadline = time.time() + _QUERY_TIMEOUT
        while time.time() < deadline:
            out = self.client.get(f"{self.base_url}/result/{uuid}")
            if out.status_code == 200:
                data = out.json()
                if data.get("success") or "stdout" in data:
                    return self._normalize(data)
            time.sleep(1.0)
        raise JoernQueryError(f"Joern query {uuid} did not finish within {_QUERY_TIMEOUT:.0f}s")

    @staticmethod
    def _normalize(data: dict) -> dict:
        text = data.get("stdout") or data.get("response") or ""
        if data.get("stderr"):
            text += "\n" + data["stderr"]
        text = _ANSI.sub("", text)
        return {**data, "stdout": text, "response": text}

    # ── Project lifecycle ───────────────────────────────────────────────────

    def import_project(self, input_path: Path, project: str) -> int:
        """Build a Python CPG for a directory. Returns the method count."""
        try:
            out = self._execute_raw(build_import_query(Path(input_path).as_posix(), project))
        except httpx.RequestError as e:
            raise JoernConnectionError(f"Failed to reach Joern during import: {e}")
        except httpx.HTTPStatusError as e:
            raise JoernQueryError(f"Joern import failed: HTTP {e.response.status_code}")
        count = _between(_value_text(out["stdout"], IMPORT_BEGIN), IMPORT_BEGIN, IMPORT_END)
        if count is None or not count.strip().isdigit():
            raise JoernQueryError(f"Failed to import code: {out['stdout'][-300:]}")
        return int(count.strip())

    def delete_project(self, project: str) -> None:
        try:
            self._execute_raw(build_delete_query(project))
        except (httpx.HTTPError, JoernQueryError) as e:
            logger.warning(f"Could not delete Joern project {project}: {e}")

    # Kept for callers that still create a workspace first; importing a
    # project is all Joern needs.
    def create_workspace(self, workspace_name: str) -> None:
        return None

    def import_code(self, target_path: Path, workspace_name: str = "") -> None:
        target = Path(target_path)
        self.import_project(target if target.is_dir() else target.parent, workspace_name or "hackersec")

    # ── Queries ─────────────────────────────────────────────────────────────

    def query_taint(
        self,
        workspace_name: str,
        file_name: str,
        line_num: int,
        sink_name: str | None = None,
        source_regex: str | None = None,
        method_line: int | None = None,
    ) -> dict:
        """
        Data flows from untrusted sources into the call on `line_num`.

        `workspace_name` is unused (the imported project is active); it stays
        in the signature for existing callers. The optional arguments apply an
        LLM-labelled source/sink specification (see `build_taint_query`).
        """
        query = build_taint_query(
            line_num,
            file_hint=file_name or None,
            sink_name=sink_name,
            extra_source_regex=source_regex,
            method_line=method_line,
        )
        try:
            res = self._execute_raw(query)
        except httpx.RequestError as e:
            raise JoernConnectionError(f"Failed to reach Joern during taint query: {e}")
        except httpx.HTTPStatusError as e:
            raise JoernQueryError(f"Taint query failed: HTTP {e.response.status_code}")

        output = (res.get("stdout") or res.get("response") or "").strip()

        payload = _between(_value_text(output, TAINT_BEGIN), TAINT_BEGIN, TAINT_END)
        if payload is not None:
            try:
                data = json.loads(payload)
            except json.JSONDecodeError as e:
                raise JoernQueryError(f"Unparseable taint result: {e}")
            flows = data.get("flows") or []
            return {
                "cpg_status": "success" if flows else "no_flow_found",
                "taint_paths": flows,
                "sink_calls": data.get("sinks", 0),
                "sources": data.get("sources", 0),
            }

        # Plain JSON array or a "no flows" message.
        if not (output.startswith("[") and output.endswith("]")):
            if "No flows" in output or "empty" in output:
                return {"cpg_status": "no_flow_found", "taint_paths": []}
            raise JoernQueryError(f"Unexpected Joern query output: {output[:300]}")
        try:
            flows = json.loads(output)
        except json.JSONDecodeError as e:
            raise JoernQueryError(f"Failed to query taint flow: {e}")
        if not flows:
            return {"cpg_status": "no_flow_found", "taint_paths": []}
        return {"cpg_status": "success", "taint_paths": flows}
