"""Dynamic exploit verification stage.

`verify_finding` reproduces a candidate vulnerability by executing the real
flagged code against a malicious payload inside a hardened Docker sandbox
(`sandbox.py`), using per-CWE probes (`oracles.py`). It sets:

    finding.reproduced     True | False | None
    finding.repro_evidence {status, marker?, stdout?}

Only runs for verdicts worth confirming (true_positive / uncertain) and CWE
classes with a code-level oracle; everything else stays reproduced=None.
"""
import logging

from hackersec.analysis.verify.oracles import build_probe, detect, ORACLE_CWES
from hackersec.analysis.verify.sandbox import run_driver_in_docker

logger = logging.getLogger(__name__)

VERIFY_VERDICTS = {"true_positive", "uncertain"}


def verify_finding(finding, *, job_id: str = "standalone", runner=None):
    """Attempt to reproduce `finding`; mutate + return it.

    runner: injectable `(files, driver, *, timeout) -> {status, stdout, ...}`
    for tests. Defaults to the real Docker sandbox.
    """
    runner = runner or run_driver_in_docker

    if finding.fusion_verdict not in VERIFY_VERDICTS:
        finding.reproduced = None
        finding.repro_evidence = {"status": "skipped_verdict"}
        return finding

    if not (set(finding.cwe_ids or []) & ORACLE_CWES):
        finding.reproduced = None
        finding.repro_evidence = {"status": "not_checkable"}
        return finding

    probe = build_probe(finding)
    if probe is None:
        finding.reproduced = None
        finding.repro_evidence = {"status": "no_driver"}
        return finding

    marker = probe["marker"]

    # Run the exploit payload first.
    payload = runner(probe["files"], probe["payload_driver"], timeout=20)
    if payload.get("status") != "ran":
        finding.reproduced = None
        finding.repro_evidence = {"status": payload.get("status")}
        logger.info(f"[{job_id}] verify inconclusive ({payload.get('status')}) for "
                    f"{finding.file_path}:{finding.line_start}")
        return finding
    payload_fired = detect(payload.get("stdout", ""), marker)

    # Differential control run: benign input through the same function. A real
    # vuln fires with the payload and stays silent here; a hardcoded/faked PoC
    # prints the marker regardless of input → we reject it as not reproduced.
    control = runner(probe["files"], probe["control_driver"], timeout=20)
    control_fired = control.get("status") == "ran" and detect(control.get("stdout", ""), marker)

    reproduced = bool(payload_fired and not control_fired)
    finding.reproduced = reproduced
    finding.repro_evidence = {
        "status": "reproduced" if reproduced
                  else "hardcoded_rejected" if (payload_fired and control_fired)
                  else "not_triggered",
        "marker": marker,
        "payload_fired": payload_fired,
        "control_fired": control_fired,
        "stdout": (payload.get("stdout") or "")[:500],
    }
    logger.info(f"[{job_id}] verify reproduced={reproduced} "
                f"(payload={payload_fired}, control={control_fired}) for "
                f"{finding.file_path}:{finding.line_start}")
    return finding
