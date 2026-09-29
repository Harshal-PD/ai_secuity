"""
Joern (Scala) queries sent to the Joern server.

Each query evaluates to one string wrapped in markers. The server returns the
REPL's rendering of that value (`val res3: String = "<<HS_...>>...`), while
`println` output only reaches the Joern container's own log, so the value is
the only channel back.
"""

IMPORT_BEGIN, IMPORT_END = "<<HS_IMPORT>>", "<</HS_IMPORT>>"
TAINT_BEGIN, TAINT_END = "<<HS_TAINT>>", "<</HS_TAINT>>"

# Python user-input entry points, matched against a call's full source text.
PYTHON_SOURCE_REGEX = (
    r"(?s).*("
    r"request\.(args|form|values|GET|POST|cookies|headers|data|json|files|query_params|body|params|get_json)"
    r"|sys\.argv|os\.environ|getenv\(|input\(|raw_input\(|\.recv\(|urlopen\(|stdin\.read"
    r").*"
)

MAX_FLOWS = 5


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

    return f"""locally {{
  def hsEsc(s: String): String = s.flatMap {{
    case '"' => "\\\\\\""
    case '\\\\' => "\\\\\\\\"
    case c if c.isControl => " "
    case c => c.toString
  }}
  val hsInFile = cpg.call.lineNumber({int(sink_line)}){file_filter}.l
  val hsOnLine = if (hsInFile.nonEmpty) hsInFile else cpg.call.lineNumber({int(sink_line)}).l
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
