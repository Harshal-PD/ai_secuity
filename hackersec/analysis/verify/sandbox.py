"""Hardened, ephemeral Docker sandbox for executing exploit probes.

This runs ATTACKER-CONTROLLED payloads, so isolation is a hard security
boundary, not a nicety. Every container is: no network, non-root, read-only
rootfs (writable tmpfs only), all caps dropped, no-new-privileges, resource
capped, and force-removed. If Docker is unavailable we return
`sandbox_unavailable` and NEVER fall back to running payloads on the host.

# ponytail: Docker/runc is the pragmatic default. For untrusted code the 2026
# upgrade path is gVisor (`--runtime=runsc`) or Firecracker/Kata microVMs —
# swap the runtime flag in DOCKER_BASE when the threat model demands it.
"""
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "python:3.12-slim"

# Hardening flags applied to every probe container.
DOCKER_HARDENING = [
    "--rm",
    "--network", "none",
    "--user", "65534:65534",           # nobody
    "--read-only",                      # immutable rootfs
    "--tmpfs", "/tmp:rw,size=16m,noexec",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "256m",
    "--cpus", "1",
]


def docker_available() -> bool:
    """True if the docker CLI exists and the daemon responds."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def run_driver_in_docker(files: dict, driver: str, *, timeout: int = 20,
                         image: str = DEFAULT_IMAGE) -> dict:
    """Run `driver` (Python) in a hardened container with `files` mounted read-only.

    files: {relative_name: content} written into the mounted /work dir.
    Returns {status, stdout, exit_code}. status:
      "ran"                 -> container executed (inspect stdout for the oracle marker)
      "timeout"             -> killed after `timeout`s
      "sandbox_unavailable" -> docker missing/broken; caller must treat as None
      "error"               -> unexpected failure launching the container
    """
    if not docker_available():
        return {"status": "sandbox_unavailable", "stdout": "", "exit_code": None}

    workdir = Path(tempfile.mkdtemp(prefix="hs_verify_"))
    try:
        for name, content in files.items():
            (workdir / name).write_text(content, encoding="utf-8", errors="replace")
        (workdir / "driver.py").write_text(driver, encoding="utf-8", errors="replace")

        cmd = (
            ["docker", "run"]
            + DOCKER_HARDENING
            + ["-v", f"{workdir}:/work:ro", "-w", "/work", image,
               "python", "/work/driver.py"]
        )
        logger.info(f"[verify] sandbox run: image={image} timeout={timeout}s")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "stdout": "", "exit_code": None}

        return {
            "status": "ran",
            "stdout": (r.stdout or "") + (r.stderr or ""),
            "exit_code": r.returncode,
        }
    except Exception as e:
        logger.error(f"[verify] sandbox launch failed: {e}")
        return {"status": "error", "stdout": str(e), "exit_code": None}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
