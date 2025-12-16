import streamlit as st
import json, os
from llm_client import LLMClient
from scanner import keyword_check, llm_as_judge
from reporter import generate_report

CONFIG_FILE = "llm_config.json"

def load_cfg():
    return json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else {}

def save_cfg(cfg):
    json.dump(cfg, open(CONFIG_FILE, "w"), indent=2)

st.set_page_config("AI LLM Vulnerability Scanner", "🛡️", "wide")
st.title("🛡️ AI LLM Vulnerability Scanner")

# ================= SIDEBAR CONFIG =================
st.sidebar.title("🔧 LLM Configuration")
cfg = load_cfg()

provider = st.sidebar.selectbox("Provider", ["openai","deepseek","gemini","custom"],
                                index=["openai","deepseek","gemini","custom"].index(cfg.get("provider","custom")))
base_url = st.sidebar.text_input("Base URL", cfg.get("base_url",""))
model = st.sidebar.text_input("Model", cfg.get("model",""))
api_key = st.sidebar.text_input("API Key", type="password", value=cfg.get("api_key",""))

if st.sidebar.button("💾 Save"):
    save_cfg({
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "api_key": api_key
    })
    st.sidebar.success("Saved")

cfg = load_cfg()
if not cfg.get("base_url"):
    st.stop()

llm = LLMClient(cfg)

# ================= MODE SELECT =================
mode = st.radio("Select Mode", ["💬 Live Chat", "🧪 Perform Test Scenarios"], horizontal=True)

# ================= LIVE CHAT =================
if mode == "💬 Live Chat":
    if "chat" not in st.session_state:
        st.session_state.chat = []

    for m in st.session_state.chat:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])

    p = st.chat_input("Ask something")
    if p:
        st.session_state.chat.append({"role":"user","content":p})
        with st.chat_message("assistant"):
            r = llm.chat(p)
            st.markdown(r)
            st.session_state.chat.append({"role":"assistant","content":r})

# ================= SCAN MODE =================
if mode == "🧪 Perform Test Scenarios":
    st.subheader("Upload Custom Scan Pack or Use OWASP")

    uploaded = st.file_uploader("Upload Scan JSON", type="json")
    if uploaded:
        scan = json.load(uploaded)
    else:
        scan = json.load(open("scans/owasp_llm_top10.json"))

    if st.button("▶ Execute Scan"):
        results = []

        for t in scan["tests"]:
            st.markdown(f"### {t['id']} – {t['category']}")
            st.code(t["prompt"])

            response = llm.chat(t["prompt"])
            with st.expander("📄 LLM Response"):
                st.markdown(response)

            keyword_vuln = keyword_check(response, t["fail_keywords"])

            judge_raw = llm_as_judge(llm, t["prompt"], response)
            try:
                judge = json.loads(judge_raw)
                vulnerable = judge["vulnerable"]
                severity = judge["severity"]
                reason = judge["reason"]
            except:
                vulnerable = keyword_vuln
                severity = "Medium"
                reason = "Fallback keyword detection"

            st.markdown(f"**Result:** {'❌ Vulnerable' if vulnerable else '✅ Safe'}")
            st.markdown(f"**Severity:** {severity}")
            st.markdown(f"**Reason:** {reason}")

            results.append({
                "id": t["id"],
                "category": t["category"],
                "prompt": t["prompt"],
                "response": response,
                "vulnerable": vulnerable,
                "severity": severity,
                "reason": reason
            })

        report_file = generate_report(scan["scan_name"], results)
        st.success("Scan Completed")
        st.download_button("📄 Download Report", open(report_file).read(), file_name=report_file)
