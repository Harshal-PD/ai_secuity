import shutil
import tempfile
import logging
from pathlib import Path

from hackersec.worker.celery_app import celery_app
from hackersec.db import store
from hackersec.analysis.static import run_static_analysis
from hackersec.analysis.dedup import dedup_findings, summarize_findings
from hackersec.ingestion.git_clone import clone_repo

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="hackersec.worker.tasks.run_analysis", max_retries=0)
def run_analysis(self, job_id: str, target: str, target_type: str):
    """Main analysis pipeline task. Orchestrates static analysis pipeline."""
    logger.info(f"[{job_id}] Starting analysis — target_type={target_type}")
    store.update_job(job_id, status="running")
    tmpdir = Path(tempfile.mkdtemp(prefix="hackersec_"))

    try:
        # ── Step 1: Prepare target path ──────────────────────────────────
        if target_type == "git_url":
            logger.info(f"[{job_id}] Cloning {target}")
            target_path = clone_repo(target, tmpdir / "repo")
        else:
            target_path = Path(target)
            if not target_path.exists():
                raise FileNotFoundError(f"Uploaded file not found: {target}")
                
            if target_path.name.endswith(".zip"):
                import zipfile
                logger.info(f"[{job_id}] Extracting zip archive: {target_path.name}")
                extract_dir = tmpdir / "repo"
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                target_path = extract_dir

        # ── Step 2: Static analysis ───────────────────────────────────────
        logger.info(f"[{job_id}] Running static analysis on {target_path}")
        raw_findings = run_static_analysis(target_path, job_id=job_id)
        logger.info(f"[{job_id}] Raw findings: {len(raw_findings)}")

        # ── Step 3: Deduplication ─────────────────────────────────────────
        findings = dedup_findings(raw_findings)
        logger.info(f"[{job_id}] After dedup: {len(findings)} findings")

        # ── Step 3.5 / 3.7: CPG + RAG Enrichment ──────────────────────────
        # Shared with the evaluation harness so reported metrics reflect this
        # exact enrichment path.
        from hackersec.analysis.enrich import enrich_with_cpg, enrich_with_rag

        enrich_with_cpg(findings, target_path, job_id=job_id)
        enrich_with_rag(findings, job_id=job_id)


        # ── Step 3.8: Adversarial Board (Attacker → Defender → Judge) ─────
        from hackersec.analysis.llm.client import OllamaClient
        from hackersec.analysis.llm.board import AdversarialBoard

        llm_client = OllamaClient()

        try:
            board = AdversarialBoard(client=llm_client)
            for f in findings:
                logger.info(f"[{job_id}] Convening board for {f.file_path}:{f.line_start}")

                verdict = board.deliberate(f)
                f.llm_analysis = verdict

                if verdict.get("llm_status") == "success":
                    logger.info(
                        f"[{job_id}] Board ruled {verdict['board_verdict']} "
                        f"(P_real={verdict['confidence']}) for {f.file_path}:{f.line_start}"
                    )

            logger.info(f"[{job_id}] LLM board deliberation complete")

        except Exception as e:
            logger.error(f"[{job_id}] LLM pipeline gracefully bounded exceptions: {e}")
            for f in findings:
                if not getattr(f, 'llm_analysis', None):
                    f.llm_analysis = {"llm_status": "failed_connection", "error": str(e)}

        # ── Step 3.9: ML Fusion Inference ─────────────────────────────────
        from hackersec.analysis.ml.inference import FusionClassifier
        
        try:
            # Reusing local cache object initialized for matrix isolation
            classifier = FusionClassifier()
            for f in findings:
                res = classifier.predict(f)
                # Map verdict output dynamically to DB persistence bounds
                # SHAP components get strictly mapped safely stringified via json dumps
                f.fusion_verdict = res["prediction"]
                # We could append SHAP to fusion_verdict implicitly as string 
                # To maintain database integrity without adding another schema column:
                if res.get("shap_values"):
                    f.llm_analysis["shap_values"] = res["shap_values"]
                    
            logger.info(f"[{job_id}] ML Classifier fusion completion")
            
        except Exception as e:
            logger.error(f"[{job_id}] ML Inference crashed gracefully: {e}")
            for f in findings:
                 if not f.fusion_verdict:
                     f.fusion_verdict = "uncertain"

        # ── Step 3.10: Patch Generation ───────────────────────────────────
        from hackersec.analysis.patch import build_patch_prompt, parse_patch, compute_diff, validate_patch
        
        from hackersec.analysis.llm.client import MODEL_PATCHER

        try:
            for f in findings:
                if f.fusion_verdict == "true_positive" and f.code_snippet:
                    logger.info(f"[{job_id}] Generating patch for true positive at {f.file_path}:{f.line_start}")
                    
                    prompt = build_patch_prompt(f)
                    # The patcher emits raw source, so JSON-constrained decoding is off.
                    llm_res = llm_client.generate(
                        prompt,
                        model=MODEL_PATCHER,
                        json_mode=False,
                        temperature=0.1,
                    )
                    
                    if llm_res["llm_status"] == "success":
                        raw_patch = parse_patch(llm_res["response"])
                        
                        # Generate literal unified diff strings
                        diff_text = compute_diff(f.code_snippet, raw_patch)
                        f.patch = diff_text
                        
                        # Execute Semgrep rules verification on patched outputs
                        status = validate_patch(f, raw_patch)
                        f.patch_status = status
                    else:
                        f.patch_status = "failed_generation"
                        
            logger.info(f"[{job_id}] Patching validation loops complete")
            
        except Exception as e:
             logger.error(f"[{job_id}] Patch generation failed elegantly: {e}")
             for f in findings:
                 if f.fusion_verdict == "true_positive" and not f.patch_status:
                     f.patch_status = "error"

        # ── Step 4: Store results ─────────────────────────────────────────
        store.save_findings(job_id, findings)
        store.update_job(job_id, status="complete", finding_count=len(findings))
        logger.info(f"[{job_id}] Analysis complete")

    except Exception as exc:
        logger.error(f"[{job_id}] Analysis failed: {exc}", exc_info=True)
        store.update_job(job_id, status="failed", error=str(exc))
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
