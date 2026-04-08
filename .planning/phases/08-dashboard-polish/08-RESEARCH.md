# Phase 8 Research: Dashboard & Polish

## RESEARCH COMPLETE

**Phase:** 8 — Dashboard & Polish
**Goal:** Build a "wow-factor" Web Dashboard achieving complete project visualization bridging Python logic explicitly into a modern, aesthetic frontend.

---

## 1. Frontend Framework & Aesthetics

Per project architecture notes, we will build the Dashboard using **React + Vite** with **Vanilla CSS** achieving custom Glassmorphism and dark-mode aesthetic dynamics seamlessly without generic styling limitations.
- **Charts:** `Recharts` mapping F1 Metrics bounding baseline Semgrep vs HackerSec Precision mathematically.
- **Typography/Animations:** Utilizing Google Fonts (`Outfit`, `Inter`) integrating native micro-animations responding to hover states maximizing premium UI feels exactly matching user directives.

## 2. API Connectivity Constraints

FastAPI backend endpoints MUST handle cross-origin constraints (CORS).
We will inject `fastapi.middleware.cors.CORSMiddleware` inside `hackersec/main.py`.
Required endpoints extending mapping:
- `POST /analyze` (Existing)
- `GET /jobs/{job_id}` (Existing)
- `GET /metrics` -> Parsing `eval_results/` latest JSON matrix.

## 3. UI Composition Strategy

1. **Upload View:** Aesthetic drag-and-drop bounding file inputs. Dynamic processing bars bridging standard 2-minute limits.
2. **Analysis Report Matrix:** Dynamic `Grid` layouts iterating `Finding` elements parsing `true_positive` bounds securely displaying `SHAP`, `Diff`, and `Rule`.
3. **Analytics Tab:** `Recharts` rendering grouped bars summarizing pipeline efficiency bounds elegantly.

## Validation Strategy
- End-to-end local host executions mapped against mock Python files verifying finding lists execute beautifully matching precise aesthetic requirements strictly securely.
