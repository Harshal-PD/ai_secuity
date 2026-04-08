# Plan 01-02 Summary

## What was built
- Finding dataclass and severity maps implemented in `hackersec/analysis/schema.py`.
- Language detector (`hackersec/ingestion/detector.py`) implemented utilizing `LANGUAGE_MAP`.
- Git cloning helper (`hackersec/ingestion/git_clone.py`) and file upload saving helper (`hackersec/ingestion/file_upload.py`) implemented.
- Semgrep and Bandit integration implemented in `hackersec/analysis/static.py` running via subprocess, with output parsed to normalize Findings schema.

## Completed Tasks
- [x] Task 1: Finding Schema
- [x] Task 2: Language Detector + Ingestion Helpers
- [x] Task 3: Semgrep Runner
