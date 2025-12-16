import streamlit as st
import json
import os
from llm_client import LLMClient
from scanner import evaluate_response, calculate_score

CONFIG_FILE = "llm_config.json"

# ------------------ Helpers ------------------
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def load_scan(path):
    with open(path, "r") as f:
        return json.load(f)

# ------------------ Page Setup ------------------
st.set_page_config(
    page_title="AI LLM Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI LLM Vulnerability Scanner")

# =================================================
# 🔧 SIDEBAR – LLM CONFIGURATION (ALWAYS VISIBLE)
# =================================================
st.sidebar.title("🔧 LLM Configuration")

existing_cfg = load_config()

provider = st.sidebar.selectbox(
    "Provider",
    ["openai", "deepseek", "gemini", "custom"],
    index=["openai", "deepseek", "gemini", "custom"].index(
        existing_cfg.get("provider", "custom")
    )
)

base_url = st.sidebar.text_input(
    "Base URL",
    value=existing_cfg.get("base_url", "")
)

model = st.sidebar.text_input(
    "Model",
    value=existing_cfg.get("model", "")
)

api_key = st.sidebar.text_input(
    "API Key",
    type="password",
    value=existing_cfg.get("api_key", "")
)

timeout = st.sidebar.number_input(
    "Timeout (seconds)",
    min_value=5,
    max_value=120,
    value=int(existing_cfg.get("timeout", 60))
)

auth_header = st.sidebar.text_input(
    "Auth Header",
    value=existing_cfg.get("auth_header", "Authorization")
)

auth_prefix = st.sidebar.text_input(
    "Auth Prefix",
    value=existing_cfg.get("auth_prefix", "Bearer")
)

if st.sidebar.button("💾 Save Configuration"):
    cfg = {
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "timeout": timeout,
        "auth_header": auth_header,
        "auth_prefix": auth_prefix
    }
    save_config(cfg)
    st.sidebar.success("LLM configuration saved")

st.sidebar.markdown("---")

config = load_config()

if not config or not config.get("base_url") or not config.get("model"):
    st.sidebar.warning("LLM not fully configured")
    st.stop()

st.sidebar.success("LLM ready")

llm = LLMClient(config)

# =================================================
# 🧭 MAIN MODE SELECTION
# =================================================
mode = st.radio(
    "Choose Operation Mode",
    ["💬 Live Chat", "🧪 Perform Test Scenarios"],
    horizontal=True
)

# =================================================
# 💬 LIVE CHAT MODE
# =================================================
if mode == "💬 Live Chat":
    st.subheader("💬 Live Chat")

    if "chat" not in st.session_state:
        st.session_state.chat = []

    for msg in st.session_state.chat:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    prompt = st.chat_input("Enter your message")

    if prompt:
        st.session_state.chat.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            response = llm.chat(prompt)
            st.markdown(response)
            st.session_state.chat.append(
                {"role": "assistant", "content": response}
            )

# =================================================
# 🧪 TEST SCENARIO MODE
# =================================================
if mode == "🧪 Perform Test Scenarios":
    st.subheader("🧪 Security Test Scenarios")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("OWASP LLM Top 10"):
            st.session_state.run_owasp = True

    if st.session_state.get("run_owasp"):
        scan = load_scan("scans/owasp_llm_top10.json")

        st.markdown(f"## {scan['scan_name']}")
        st.caption(scan["description"])

        results = []
        progress = st.progress(0)
        total = len(scan["tests"])

        for i, test in enumerate(scan["tests"], 1):
            st.markdown(f"### {test['id']} – {test['category']}")
            st.code(test["prompt"])

            response = llm.chat(test["prompt"])

            vulnerable = evaluate_response(
                response,
                test["fail_keywords"]
            )

            status = "❌ Vulnerable" if vulnerable else "✅ Safe"
            st.markdown(f"**Result:** {status}")

            results.append({
                "id": test["id"],
                "category": test["category"],
                "vulnerable": vulnerable
            })

            progress.progress(i / total)

        score = calculate_score(results)

        # ---------- Summary ----------
        st.markdown("## 📊 Scan Summary")
        st.metric("Overall Risk Score", f"{score} / 100")

        vulns = {}
        for r in results:
            if r["vulnerable"]:
                vulns[r["category"]] = vulns.get(r["category"], 0) + 1

        if vulns:
            st.error("### 🚨 Vulnerabilities Detected")
            for cat, count in vulns.items():
                st.write(f"- **{cat}**: {count}")
        else:
            st.success("No vulnerabilities detected")

        st.session_state.run_owasp = False
