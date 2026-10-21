"""
Joern (Scala) queries sent to the Joern server.

Each query evaluates to one string wrapped in markers. The server returns the
REPL's rendering of that value (`val res3: String = "<<HS_...>>...`), while
`println` output only reaches the Joern container's own log, so the value is
the only channel back.
"""

import re

IMPORT_BEGIN, IMPORT_END = "<<HS_IMPORT>>", "<</HS_IMPORT>>"
TAINT_BEGIN, TAINT_END = "<<HS_TAINT>>", "<</HS_TAINT>>"

# Python user-input entry points, matched against a call's full source text.
PYTHON_SOURCE_REGEX = (
    r"(?s).*("
    r"request\.(args|form|values|GET|POST|cookies|headers|data|json|files|query_params|body|params|get_json)"
    r"|sys\.argv|os\.environ|getenv\(|input\(|raw_input\(|\.recv\(|urlopen\(|stdin\.read"
    r").*"
)

# Sanitizer / validation calls along a Joern taint path or intermediate guard line.
_SANITIZER_FLOW_RE = re.compile(
    r"(\b(escape|quote|quote_plus|shlex\.quote|pipes\.quote|html\.escape|markupsafe"
    r"|bleach\.clean|clean|sanitize\w*|validate\w*|verify\w*|check_\w*|is_safe\w*|safe_join|safe_\w*"
    r"|secure_filename|has_perm\w*|realpath|abspath|normpath|commonpath|basename"
    r"|url_has_allowed_host_and_scheme|is_safe_url|urlparse|urlsplit"
    r"|int|float|bool|UUID|ip_address|isinstance|isdigit|isalnum|isalpha)\s*\("
    r"|\.startswith\s*\("
    r"|\.resolve\s*\()",
    re.I,
)
_GUARD_IF_RE = re.compile(
    r"^\s*if\b.*(\.\.|startswith|isinstance|realpath|abspath|normpath|commonpath|not\s+in\b|\bin\s+[\(\[\{]|is_safe|check_|valid|has_perm)",
    re.I,
)
_EARLY_EXIT_RE = re.compile(r"^\s*(raise|return)\b")

MAX_FLOWS = 5


def is_sanitized_flow(flow: list[dict], source_lines: list[str] | None = None) -> bool:
    """True when any node on `flow` (or an intermediate guard line between the
    flow's start and sink lines) applies a sanitizer or validation check."""
    if not flow:
        return False
    for node in flow:
        code = str((node or {}).get("code") or "")
        if _SANITIZER_FLOW_RE.search(code):
            return True

    if source_lines:
        lines = [int(n.get("line", -1)) for n in flow if isinstance(n, dict) and int(n.get("line", -1)) > 0]
        if lines:
            lo = max(1, min(lines))
            hi = min(len(source_lines), max(lines))
            for idx in range(lo - 1, hi):
                line_text = source_lines[idx]
                if idx + 1 < hi and _SANITIZER_FLOW_RE.search(line_text):
                    return True
                if _GUARD_IF_RE.search(line_text):
                    window = source_lines[idx : min(hi, idx + 3)]
                    if any(_EARLY_EXIT_RE.search(w) or "raise " in w or "return " in w for w in window):
                        return True
    return False


def classify_taint_paths(
    flows: list[list[dict]], source_lines: list[str] | None = None
) -> tuple[list[list[dict]], list[list[dict]]]:
    """Split Joern `taint_paths` into `(unfiltered_flows, sanitized_flows)`."""
    unfiltered: list[list[dict]] = []
    sanitized: list[list[dict]] = []
    for f in flows or []:
        if is_sanitized_flow(f, source_lines):
            sanitized.append(f)
        else:
            unfiltered.append(f)
    return unfiltered, sanitized


def _scala_str(value: str) -> str:
    """Quote a Python string as a Scala string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_import_query(input_path: str, project: str) -> str:
    """Build a Python CPG for `input_path` (a directory) as project `project`."""
    return f"""locally {{
  scala.util.Try(delete({_scala_str(project)}))
  importCode.python(inputPath = {_scala_str(input_path)}, projectName = {_scala_str(project)})
  "{IMPORT_BEGIN}" + cpg.method.size + "{IMPORT_END}"
}}"""


def build_delete_query(project: str) -> str:
    return f"scala.util.Try(delete({_scala_str(project)}))"


def source_regex(callees: list[str]) -> str | None:
    """Regex matching calls to any of `callees` (dotted names such as
    `flask.request.get_json`), for sources labelled by the LLM."""
    names = [c for c in callees if c]
    if not names:
        return None
    return r"(?s).*(" + "|".join(r"\Q" + c.replace(r"\E", "") + r"\E" for c in names) + r").*"


def build_taint_query(
    sink_line: int,
    file_hint: str | None = None,
    sink_name: str | None = None,
    extra_source_regex: str | None = None,
    method_line: int | None = None,
    sink_end_line: int | None = None,
) -> str:
    """
    Find data flows from untrusted sources into the arguments of the call(s)
    on `sink_line`.

    Sources are the parameters of every function in the project (callers
    control them) plus known Python input APIs; parameters without a line are
    Joern's synthetic library stubs and are skipped. The receiver (argument 0) is
    not a sink: a parameter reaching `cur` in `cur.execute(...)` is not taint
    reaching the query. A line with no real call (Bandit's B608 points at
    `q = "SELECT ..." + x`) falls back to its operator expressions. `file_hint`
    restricts the sink to one file when the project holds several; if nothing
    matches it, the line is looked up across the project.

    For LLM-labelled specifications: `sink_name` keeps only calls of that name
    on the line, `extra_source_regex` adds labelled source calls, and
    `method_line` limits parameter sources to the function defined there.
    """
    if file_hint:
        file_filter = f'.where(_.file.name(".*\\\\Q" + {_scala_str(file_hint)} + "\\\\E"))'
    else:
        file_filter = ""

    if sink_name:
        named = f'val hsNamed = hsOnLine.filter(_.name == {_scala_str(sink_name)})'
        real = 'val hsReal = if (hsNamed.nonEmpty) hsNamed else hsOnLine.filterNot(_.name.startsWith("<operator>"))'
    else:
        named = ""
        real = 'val hsReal = hsOnLine.filterNot(_.name.startsWith("<operator>"))'

    all_params = 'cpg.method.parameter.filter(_.lineNumber.isDefined).filterNot(p => p.name == "self" || p.name == "cls").l'
    if method_line:
        ml = int(method_line)
        params = f"""val hsAt = cpg.method.lineNumber({ml}){file_filter}.l
  val hsNear = if (hsAt.nonEmpty) hsAt else cpg.method.filter(_.lineNumber.exists(l => l >= {ml - 3} && l <= {ml + 3})){file_filter}.l
  val hsParams = if (hsNear.nonEmpty) hsNear.parameter.filterNot(p => p.name == "self" || p.name == "cls").l else {all_params}"""
    else:
        params = f"val hsParams = {all_params}"

    inputs = f"cpg.call.code({_scala_str(PYTHON_SOURCE_REGEX)}).l"
    if extra_source_regex:
        inputs = f"({inputs} ++ cpg.call.code({_scala_str(extra_source_regex)}).l).distinct"

    start_l = int(sink_line)
    end_l = int(max(start_l, sink_end_line or start_l))
    if end_l > start_l:
        line_sel = f".filter(_.lineNumber.exists(l => l >= {start_l} && l <= {end_l}))"
    else:
        line_sel = f".lineNumber({start_l})"
    near_sel = f".filter(_.lineNumber.exists(l => l >= {start_l} && l <= {end_l + 2}))"

    return f"""locally {{
  def hsEsc(s: String): String = s.flatMap {{
    case '"' => "\\\\\\""
    case '\\\\' => "\\\\\\\\"
    case c if c.isControl => " "
    case c => c.toString
  }}
  val hsExact = cpg.call{line_sel}{file_filter}.l
  val hsInFile = if (hsExact.nonEmpty) hsExact else cpg.call{near_sel}{file_filter}.l
  val hsOnLine = if (hsInFile.nonEmpty) hsInFile else cpg.call{line_sel}.l
  {named}
  {real}
  val hsSinks = if (hsReal.nonEmpty) hsReal else hsOnLine
  val hsSinkArgs = hsSinks.flatMap(_.argument.l.filter(_.argumentIndex >= 1))
  {params}
  val hsInputs = {inputs}
  val hsFlows = if (hsSinkArgs.isEmpty) List() else hsSinkArgs.reachableByFlows(hsParams, hsInputs).l.take({MAX_FLOWS})
  val hsJson = hsFlows.map {{ f =>
    f.elements.map {{ n =>
      "{{\\"line\\":" + n.lineNumber.map(_.toString).getOrElse("-1") + ",\\"code\\":\\"" + hsEsc(n.code.take(160)) + "\\"}}"
    }}.mkString("[", ",", "]")
  }}.mkString("[", ",", "]")
  "{TAINT_BEGIN}{{\\"sinks\\":" + hsSinks.size + ",\\"sources\\":" + (hsParams.size + hsInputs.size) + ",\\"flows\\":" + hsJson + "}}{TAINT_END}"
}}"""
