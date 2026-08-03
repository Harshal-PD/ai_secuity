def build_taint_query(sink_line: int) -> str:
    """
    Builds the Joern DSL query to find taint flows reaching the given sink line.
    
    The query performs:
    1. Locating the sink via cpg.call with the specific line number
    2. Setting all identifiers as generic sources
    3. Executing reachableByFlows
    4. Mapping the resulting nodes back to their line numbers and snippet strings
    5. Formatting it natively into JSON
    """
    
    # Sources = method parameters (the canonical proxy for untrusted/external
    # input), not every identifier — a real source→sink path, meaningful for the
    # LLM PoC agent. If a method has no params, flows are simply empty (safe).
    # ponytail: parameter-level sources; widen to tagged user-input calls
    # (request.*, argv, environ) if recall on real repos falls short.
    scala_code = f"""
    val sink = cpg.call.lineNumber({sink_line}).l
    val source = cpg.parameter.l

    val flows = sink.reachableByFlows(source).map {{ flow =>
        flow.elements.map {{ node =>
            Map("line" -> node.lineNumber.getOrElse(-1), "code" -> node.code)
        }}.toList
    }}.toList
    
    // Convert to JSON string representation
    flows.toJson
    """
    return scala_code.strip()
