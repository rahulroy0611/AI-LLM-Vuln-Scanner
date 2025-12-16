# AI LLM Vulnerability Scanner

AI LLM Vulnerability Scanner is a lightweight Streamlit application to evaluate Large Language Models (LLMs) for insecure or undesired behavior using configurable test packs (e.g., OWASP-style checks). The app runs prompt-based tests against an LLM, evaluates responses (LLM-as-judge with a keyword fallback), and produces interactive dashboards, JSON scan results, and an executive PDF report.

**Features**
- Run interactive scans or live chat with an LLM
- Use configurable scan packs (JSON) — includes OWASP LLM Top10 plugin
- Dashboard visualizations for severity/category distribution
- Export raw scan JSON and an executive PDF report

**Repository layout**
- [agent.py](agent.py): Runs tests from a scan pack using `LLMClient` and returns verdicts.
- [app.py](app.py): Streamlit UI — live chat, test scenarios, dashboard, and scan history.
- [scanner.py](scanner.py): Test evaluation logic (LLM-as-judge + keyword fallback).
- [llm_client.py](llm_client.py): Minimal HTTP client for LLM chat completions.
- [reporter.py](reporter.py): JSON report generator saved to `reports/`.
- [pdf_report.py](pdf_report.py): Executive PDF generator using ReportLab.
- [dashboard.py](dashboard.py): Streamlit dashboard visuals (Altair + Pandas).
- [diff.py](diff.py): Simple diff utility to compare vulnerability counts.
- [requirements.txt](requirements.txt): Python dependencies.
- [llm_config.json](llm_config.json): Default LLM connection config used by the app.
- [`plugins/`](plugins/): Scan packs (e.g., `owasp_llm_top10.json`).
- [`scan_results/`](scan_results/): Generated scan JSON files.
- [`reports/`](reports/): JSON and PDF reports produced by the app.

**Requirements**
- Python 3.10+
- Recommended: create a virtual environment
- See `requirements.txt` for dependencies (Streamlit, requests, reportlab, python-dotenv).

**Quick start**
1. Create and activate a virtual environment (example):

```bash
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure the LLM endpoint:
- Edit [llm_config.json](llm_config.json) or use the Streamlit sidebar to set `base_url`, `model`, and `api_key`.

4. Run the app (Streamlit):

```bash
streamlit run app.py
```

5. In the UI you can:
- Use **Live Chat** to interact with the LLM
- Use **Test Scenarios** to upload or use the default scan pack and run scans
- View **Dashboard** for visual summaries
- Download raw JSON from `scan_results/` or an executive PDF from `reports/`

**Usage notes**
- Default scan pack: `plugins/owasp_llm_top10.json`.
- Scan results are timestamped and saved under `scan_results/`.
- The evaluator will first try LLM-as-judge (returns JSON); if that fails, it falls back to keyword matching defined in the scan pack.

**Extending**
- Add or modify scan packs in `plugins/` to customize tests and languages.
- Adjust `llm_client.py` (headers/prefix) for different LLM APIs.
- Integrate CI to run scans programmatically by importing `ScanAgent` and calling `run()`.

---
Generated from repository files.
