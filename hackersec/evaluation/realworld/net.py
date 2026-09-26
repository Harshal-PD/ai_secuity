"""
Network outage handling.

The DGX loses internet on a schedule. A download step that fails because the
link is down must wait and retry, never record the commit as unusable —
otherwise the dataset silently shrinks every time the connection drops.
"""

import logging
import socket
import time

from hackersec.evaluation.realworld import state

logger = logging.getLogger(__name__)

PROBE_HOSTS = [("github.com", 443), ("huggingface.co", 443), ("zenodo.org", 443)]


class NetworkDown(Exception):
    """A transient connectivity failure: retry later, do not drop the item."""


def internet_up(timeout: float = 5.0) -> bool:
    for host, port in PROBE_HOSTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def wait_for_internet(context: str) -> None:
    """Block until any probe host answers, backing off up to 5 minutes."""
    if internet_up():
        return
    delay = 30
    started = time.time()
    while not internet_up():
        waited = int(time.time() - started)
        logger.warning(f"No internet ({context}); waited {waited}s, retrying in {delay}s")
        state.update_status(waiting_for="internet", waiting_context=context, waited_seconds=waited)
        time.sleep(delay)
        delay = min(delay * 2, 300)
    logger.info(f"Internet back after {int(time.time() - started)}s ({context})")
    state.update_status(waiting_for=None, waiting_context=None, waited_seconds=0)


def with_network_retry(fn, context: str, attempts: int = 1000):
    """Run `fn`; on NetworkDown wait for the link and try again."""
    for _ in range(attempts):
        try:
            return fn()
        except NetworkDown as e:
            logger.warning(f"Network failure during {context}: {e}")
            time.sleep(10)
            wait_for_internet(context)
    raise RuntimeError(f"Gave up on {context} after {attempts} network retries")
