import streamlit as st
import json
import os
from datetime import datetime

from llm_client import LLMClient
from agent import ScanAgent
from scanner import evaluate_test
from dashboard import show_dashboard
from pdf_report import generate_pdf_report

CONFIG_FILE = "llm_config.json"
SCAN_RESULTS_DIR = "reports/scan_results"

# ===================== Helpers =====================
def load_cfg():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cfg(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def load_scan(path):
    with open(path, "r") as f:
        return json.load(f)

def save_scan_result(scan_name, cfg, results):
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"{SCAN_RESULTS_DIR}/scan_{timestamp}.json"

    payload = {
        "scan_name": scan_name,
        "executed_at": datetime.utcnow().isoformat() + "Z",
        "llm": {
            "base_url": cfg.get("base_url"),
            "model": cfg.get("model")
        },
        "summary": {
            "total_tests": len(results),
            "vulnerabilities": sum(1 for r in results if r["vulnerable"])
        },
        "results": results
    }

    with open(filename, "w") as f:
        json.dump(payload, f, indent=2)

    return filename

# ===================== Page Setup =====================
st.set_page_config(
    page_title="AI LLM Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI LLM Vulnerability Scanner")

# ===================== SIDEBAR – LLM CONFIG =====================
st.sidebar.title("🔧 LLM Configuration")

cfg = load_cfg()

base_url = st.sidebar.text_input(
    "Base URL",
    value=cfg.get("base_url", "")
)

model = st.sidebar.text_input(
    "Model",
    value=cfg.get("model", "")
)

api_key = st.sidebar.text_input(
    "API Key",
    type="password",
    value=cfg.get("api_key", "")
)

timeout = st.sidebar.number_input(
    "Timeout (seconds)",
    min_value=5,
    max_value=120,
    value=int(cfg.get("timeout", 60))
)

if st.sidebar.button("💾 Save Configuration"):
    save_cfg({
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "timeout": timeout
    })
    st.sidebar.success("Configuration saved")

cfg = load_cfg()

if not cfg.get("base_url") or not cfg.get("model"):
    st.warning("Please configure the LLM from the sidebar")
    st.stop()

llm = LLMClient(cfg)
st.sidebar.success("LLM Ready")

# ===================== MODE SELECTION =====================
mode = st.radio(
    "Mode",
    ["💬 Live Chat", "🧪 Test Scenarios", "📊 Dashboard"],
    horizontal=True
)

# ===================== LIVE CHAT =====================
if mode == "💬 Live Chat":
    st.subheader("💬 Live Chat")

    if "chat" not in st.session_state:
        st.session_state.chat = []

    for msg in st.session_state.chat:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_input = st.chat_input("Ask the LLM")

    if user_input:
        st.session_state.chat.append(
            {"role": "user", "content": user_input}
        )

        with st.chat_message("assistant"):
            response = llm.chat(user_input)
            st.markdown(response)
            st.session_state.chat.append(
                {"role": "assistant", "content": response}
            )

# ===================== TEST SCENARIOS =====================
if mode == "🧪 Test Scenarios":
    st.subheader("🧪 Security Test Scenarios")

    uploaded = st.file_uploader(
        "Upload Scan Pack (JSON)",
        type="json"
    )

    scan = (
        json.load(uploaded)
        if uploaded
        else load_scan("scans/owasp_llm_top10.json")
    )

    lang = st.selectbox("Language", ["en", "hi"], index=0)

    if st.button("▶ Run Scan"):
        agent = ScanAgent(llm, scan)

        with st.spinner("Running security tests..."):
            results = agent.run(evaluate_test, lang)

        st.session_state["scan_results"] = results
        st.session_state["scan_name"] = scan.get(
            "scan_name", "LLM Security Scan"
        )

        # ✅ SAVE RESULT TO JSON WITH TIMESTAMP
        result_file = save_scan_result(
            st.session_state["scan_name"],
            cfg,
            results
        )
        st.session_state["last_scan_file"] = result_file

        st.success("Scan completed and results saved")

    # ---------- Render Scan Results ----------
    if "scan_results" in st.session_state:
        st.markdown("## 🧾 Scan Execution Details")

        for idx, r in enumerate(st.session_state["scan_results"], 1):
            st.markdown(f"### {idx}. {r['id']} – {r['category']}")
            st.markdown(f"**Severity:** `{r['severity']}`")
            st.markdown(
                f"**Status:** {'❌ Vulnerable' if r['vulnerable'] else '✅ Safe'}"
            )
            st.markdown(f"**Reason:** {r['reason']}")

            with st.expander("📤 Prompt Sent"):
                st.code(r["prompt"])

            with st.expander("📥 LLM Response"):
                st.markdown(r["response"])

            with st.expander("📜 Compliance Mapping"):
                for fw, controls in r["compliance"].items():
                    st.write(f"**{fw}**: {', '.join(controls)}")

            st.markdown("---")

        # ---------- PDF REPORT ----------
        pdf_path = generate_pdf_report(
            st.session_state["scan_name"],
            cfg,
            st.session_state["scan_results"]
        )

        with open(pdf_path, "rb") as f:
            st.download_button(
                "📄 Download Executive PDF Report",
                f,
                file_name=os.path.basename(pdf_path),
                mime="application/pdf"
            )

        # ---------- RAW JSON DOWNLOAD ----------
        with open(st.session_state["last_scan_file"], "r") as f:
            st.download_button(
                "⬇️ Download Raw Scan JSON",
                f,
                file_name=os.path.basename(st.session_state["last_scan_file"]),
                mime="application/json"
            )

# ===================== DASHBOARD =====================
if mode == "📊 Dashboard":
    st.subheader("📊 Security Dashboard")

    if "scan_results" not in st.session_state:
        st.info("No scan results available yet")
    else:
        show_dashboard(st.session_state["scan_results"])
