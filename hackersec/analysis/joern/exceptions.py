class JoernConnectionError(Exception):
    """Raised when Joern server is unreachable."""
    pass

class JoernQueryError(Exception):
    """Raised when Joern queries fail or return invalid formats."""
    pass
