import streamlit as st
import json
import os
from datetime import datetime
import pandas as pd

from llm_client import LLMClient
from agent import ScanAgent
from scanner import evaluate_test
from dashboard import show_dashboard
from pdf_report import generate_pdf_report

# ===================== CONSTANTS =====================
CONFIG_FILE = "llm_config.json"
SCAN_RESULTS_DIR = "scan_results"
DEFAULT_SCAN_FILE = "plugins/owasp_llm_top10.json"

# ===================== SESSION STATE INIT =====================
if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None

if "scan_name" not in st.session_state:
    st.session_state["scan_name"] = None

if "last_scan_file" not in st.session_state:
    st.session_state["last_scan_file"] = None

# ===================== HELPERS =====================
def load_cfg():
    return json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else {}

def save_cfg(cfg):
    json.dump(cfg, open(CONFIG_FILE, "w"), indent=2)

def load_scan_from_path(path):
    return json.load(open(path))

def save_scan_result(scan_name, cfg, results):
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    path = f"{SCAN_RESULTS_DIR}/scan_{ts}.json"

    payload = {
        "scan_name": scan_name,
        "executed_at": datetime.utcnow().isoformat() + "Z",
        "llm": {
            "base_url": cfg["base_url"],
            "model": cfg["model"]
        },
        "results": results
    }

    with open(path, "w") as f:
        json.dump(payload, f, indent=2)

    return path

def list_scan_files():
    if not os.path.exists(SCAN_RESULTS_DIR):
        return []
    return sorted(
        [
            os.path.join(SCAN_RESULTS_DIR, f)
            for f in os.listdir(SCAN_RESULTS_DIR)
            if f.endswith(".json") and os.path.getsize(os.path.join(SCAN_RESULTS_DIR, f)) > 0
        ],
        reverse=True
    )

def load_scan_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None

# ===================== PAGE SETUP =====================
st.set_page_config(
    page_title="AI LLM Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI LLM Vulnerability Scanner")

# ===================== SIDEBAR =====================
st.sidebar.title("🔧 LLM Configuration")
cfg = load_cfg()

base_url = st.sidebar.text_input("Base URL", cfg.get("base_url", ""))
model = st.sidebar.text_input("Model", cfg.get("model", ""))
api_key = st.sidebar.text_input("API Key", type="password", value=cfg.get("api_key", ""))
timeout = st.sidebar.number_input("Timeout (seconds)", 5, 120, int(cfg.get("timeout", 60)))

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
    ["💬 Live Chat", "🧪 Test Scenarios", "📊 Dashboard", "📂 Scan History"],
    horizontal=True
)

# ===================== LIVE CHAT =====================
if mode == "💬 Live Chat":
    st.subheader("💬 Live Chat")

    if "chat" not in st.session_state:
        st.session_state["chat"] = []

    for msg in st.session_state["chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_input = st.chat_input("Ask the LLM")

    if user_input:
        st.session_state["chat"].append({"role": "user", "content": user_input})
        with st.chat_message("assistant"):
            response = llm.chat(user_input)
            st.markdown(response)
            st.session_state["chat"].append({"role": "assistant", "content": response})

# ===================== TEST SCENARIOS =====================
if mode == "🧪 Test Scenarios":
    st.subheader("🧪 Security Test Scenarios")

    uploaded_scan = st.file_uploader(
        "Upload Scan Pack (JSON)",
        type="json",
        help="Upload custom scan pack or use default OWASP scan"
    )

    scan = (
        json.load(uploaded_scan)
        if uploaded_scan
        else load_scan_from_path(DEFAULT_SCAN_FILE)
    )

    lang = st.selectbox("Language", ["en", "hi"], index=0)

    if st.button("▶ Run Scan"):
        agent = ScanAgent(llm, scan)

        with st.spinner("Running security tests..."):
            results = agent.run(evaluate_test, lang)

        st.session_state["scan_results"] = results
        st.session_state["scan_name"] = scan.get("scan_name", "LLM Security Scan")
        st.session_state["last_scan_file"] = save_scan_result(
            st.session_state["scan_name"], cfg, results
        )

        st.success("Scan completed successfully")

    # ---------- Scan Execution Details ----------
    st.markdown("## 🧾 Scan Execution Details")

    if isinstance(st.session_state["scan_results"], list) and len(st.session_state["scan_results"]) > 0:
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
                for fw, controls in r.get("compliance", {}).items():
                    st.write(f"**{fw}**: {', '.join(controls)}")

            st.markdown("---")

        # ---------- DOWNLOADS ----------
        if st.session_state["last_scan_file"]:
            with open(st.session_state["last_scan_file"], "rb") as f:
                st.download_button(
                    "⬇️ Download Raw Scan JSON",
                    f,
                    file_name=os.path.basename(st.session_state["last_scan_file"]),
                    mime="application/json"
                )

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
    else:
        st.info("Run a scan to see execution details")

# ===================== DASHBOARD =====================
if mode == "📊 Dashboard":
    if not isinstance(st.session_state["scan_results"], list):
        files = list_scan_files()
        if files:
            data = load_scan_file(files[0])
            if data:
                st.session_state["scan_results"] = data["results"]

    if isinstance(st.session_state["scan_results"], list):
        show_dashboard(st.session_state["scan_results"])
    else:
        st.info("No scan data available")

# ===================== SCAN HISTORY =====================
if mode == "📂 Scan History":
    st.subheader("📂 Scan History")

    files = list_scan_files()
    if not files:
        st.info("No scan history found")
    else:
        rows = []
        for f in files:
            data = load_scan_file(f)
            if not data:
                continue
            rows.append({
                "Timestamp": data["executed_at"],
                "Scan Name": data["scan_name"],
                "Model": data["llm"]["model"],
                "Vulnerabilities": sum(
                    1 for r in data["results"]
                    if r.get("vulnerable") is True
                    or r.get("severity", "").lower() in ["medium", "high", "critical"]
                ),
                "File": f
            })

        df = pd.DataFrame(rows)
        st.dataframe(df.drop(columns=["File"]), use_container_width=True)

        selected_ts = st.selectbox(
            "Select scan to load into Dashboard",
            df["Timestamp"].tolist()
        )

        if st.button("🔄 Load Selected Scan"):
            file_path = df[df["Timestamp"] == selected_ts]["File"].values[0]
            data = load_scan_file(file_path)
            st.session_state["scan_results"] = data["results"]
            st.session_state["scan_name"] = data["scan_name"]
            st.success("Scan loaded into Dashboard")
