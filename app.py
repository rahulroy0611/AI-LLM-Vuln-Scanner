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

if "scan_history_page" not in st.session_state:
    st.session_state["scan_history_page"] = 1

# ===================== HELPERS =====================
def load_cfg():
    return json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else {}

def save_cfg(cfg):
    json.dump(cfg, open(CONFIG_FILE, "w"), indent=2)

def load_scan_from_path(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

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
    
def list_plugin_files():
    if not os.path.exists("plugins"):
        return {}

    plugins = {}
    for f in os.listdir("plugins"):
        if f.endswith(".json"):
            path = os.path.join("plugins", f)
            try:
                with open(path, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                    scan_name = data.get("scan_name")
                    if scan_name:
                        plugins[scan_name] = path
            except Exception:
                continue

    return plugins

def test_llm_connection(cfg):
    try:
        llm = LLMClient(cfg)

        test_prompt = "Respond with only the word OK."
        response = llm.chat(test_prompt)

        if response and "ok" in response.lower():
            return True, response

        return False, response

    except Exception as e:
        return False, str(e)
    

def calc_severity(results):
    # Detect vulnerabilities robustly
    vuln_results = [
        r for r in results
        if r.get("is_vulnerable") is True
        or r.get("verdict", "").lower() in ("fail", "vulnerable")
        or r.get("severity", "").lower() in ("critical", "high", "medium", "low")
    ]

    vuln_count = len(vuln_results)

    # ✅ If truly no vulnerabilities
    if vuln_count == 0:
        return "None", "badge-ok"

    # Calculate weighted severity score
    score = 0
    for r in vuln_results:
        sev = r.get("severity", "").lower()
        score += {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }.get(sev, 1)  # default = low impact

    if score >= 16:
        return "Critical", "badge-critical"
    if score >= 8:
        return "High", "badge-high"
    if score >= 4:
        return "Medium", "badge-med"

    return "Low", "badge-low"



def compliance_gaps(results):
    gaps = set()
    for r in results:
        for k,v in r.get("compliance",{}).items():
            if r.get("vulnerable"):
                gaps.add(k)
    return list(gaps)


# ===================== PAGE SETUP =====================
st.set_page_config(
    page_title="AI LLM Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.sticky-header {
    position: sticky;
    top: 0;
    background-color: #0e1117;
    z-index: 999;
    padding: 6px 0;
    border-bottom: 1px solid rgba(255,255,255,0.15);
}
.badge {
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 600;
}
.badge-critical { background:#570C02; color:#fecaca; }
.badge-high { background:#7f1d1d; color:#fecaca; }
.badge-med { background:#78350f; color:#fde68a; }
.badge-low { background:#064e3b; color:#a7f3d0; }
.badge-ok  { background:#14532d; color:#bbf7d0; }
.badge-gap { background:#1e293b; color:#e5e7eb; margin-right:4px;}
.row-hover:hover { background: rgba(255,255,255,0.03); }
            

            
.badge-vuln-red {
    background: rgba(239,68,68,0.15);
    color: #ef4444;
}

.badge-vuln-green {
    background: rgba(34,197,94,0.15);
    color: #22c55e;
}
            
button.scan-link {
    background: none !important;
    border: none !important;
    padding: 0 !important;
    color: #e5e7eb !important;
    font-weight: 600;
    text-align: left;
}
button.scan-link:hover {
    text-decoration: underline;
    color: #ffffff !important;
}
</style>
""", unsafe_allow_html=True)


st.title("🛡️ AI LLM Vulnerability Scanner")

# ===================== SIDEBAR =====================
st.sidebar.title("🔧 LLM Configuration")
cfg = load_cfg()

base_url = st.sidebar.text_input("Base URL", cfg.get("base_url", ""))
model = st.sidebar.text_input("Model", cfg.get("model", ""))
api_key = st.sidebar.text_input("API Key", type="password", value=cfg.get("api_key", ""))
timeout = st.sidebar.number_input("Timeout (seconds)", 5, 120, int(cfg.get("timeout", 60)))

# if st.sidebar.button("💾 Save Configuration"):
#     save_cfg({
#         "base_url": base_url,
#         "model": model,
#         "api_key": api_key,
#         "timeout": timeout
#     })
#     st.sidebar.success("Configuration saved")

if st.sidebar.button("💾 Save Configuration"):

    existing_cfg = load_cfg() or {}

    # Preserve judge config if present
    judge_cfg = existing_cfg.get("judge")

    # Build updated config
    new_cfg = {
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "timeout": timeout
    }

    if judge_cfg:
        new_cfg["judge"] = judge_cfg

    # Health check
    with st.spinner("Testing LLM connection..."):
        ok, result = test_llm_connection(new_cfg)

    if ok:
        save_cfg(new_cfg)
        st.sidebar.success("✅ Configuration saved & connection verified")
    else:
        st.sidebar.error("❌ Configuration test failed")
        with st.sidebar.expander("Error details"):
            st.code(result)


    # cfg_to_test = {
    #     "base_url": base_url,
    #     "model": model,
    #     "api_key": api_key,
    #     "timeout": timeout
    # }

    # with st.spinner("Testing LLM connection..."):
    #     ok, result = test_llm_connection(cfg_to_test)

    # if ok:
    #     save_cfg(cfg_to_test)
    #     st.sidebar.success("✅ Configuration saved & connection verified")
    #     st.sidebar.caption("LLM health check successful")

    # else:
    #     st.sidebar.error("❌ Configuration test failed")
    #     st.sidebar.caption("Please verify Base URL, Model, API Key, and Timeout")

        # with st.sidebar.expander("Error details"):
        #     st.code(result)


    cfg = load_cfg()
    if not cfg.get("base_url") or not cfg.get("model"):
        st.warning("Please configure the LLM from the sidebar")
        st.stop()

llm = LLMClient(cfg)
    # st.sidebar.success("LLM Ready")

judge_cfg = cfg.get("judge")
if not judge_cfg:
    st.error("Judge LLM is not configured")
    st.stop()

llm_judge = LLMClient(judge_cfg)

# ===================== MODE SELECTION =====================
mode = st.radio(
    "Mode",
    ["💬 Live Chat", "🧪 Test Scenarios", "📊 Dashboard", "📂 Scan History"],
    horizontal=True
)

# ===================== LIVE CHAT =====================
# if mode == "💬 Live Chat":
#     st.subheader("💬 Live Chat")

#     if "chat" not in st.session_state:
#         st.session_state["chat"] = []

#     for msg in st.session_state["chat"]:
#         with st.chat_message(msg["role"]):
#             st.markdown(msg["content"])

#     user_input = st.chat_input("Ask the LLM")

#     if user_input:
#         st.session_state["chat"].append({"role": "user", "content": user_input})
#         with st.chat_message("assistant"):
#             response = llm.chat(user_input)
#             st.markdown(response)
#             st.session_state["chat"].append({"role": "assistant", "content": response})

if mode == "💬 Live Chat":
    st.subheader("💬 Live Chat")

    if "chat" not in st.session_state:
        st.session_state["chat"] = []

    # Render chat history
    for msg in st.session_state["chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Input
    user_input = st.chat_input("Ask the LLM")

    if user_input:
        # 1️⃣ Append user message FIRST
        st.session_state["chat"].append({
            "role": "user",
            "content": user_input
        })

        # 2️⃣ Force immediate rerender so user message appears instantly
        st.rerun()

# Handle assistant response if last message is from user
if st.session_state["chat"] and st.session_state["chat"][-1]["role"] == "user":
    with st.chat_message("assistant"):
        response = llm.chat(st.session_state["chat"][-1]["content"])
        st.markdown(response)

    st.session_state["chat"].append({
        "role": "assistant",
        "content": response
    })



# ===================== TEST SCENARIOS =====================

if mode == "🧪 Test Scenarios":
    st.subheader("🧪 Security Test Scenarios")

    plugins = list_plugin_files()

    if not plugins:
        st.error("No scan plugins found in plugins/ directory")
        st.stop()

    selected_scan_name = st.selectbox(
        "Select Scan Pack",
        list(plugins.keys())
    )

    scan_file_path = plugins[selected_scan_name]
    scan = load_scan_from_path(scan_file_path)

    if st.button("▶ Run Scan"):
        agent = ScanAgent(llm, llm_judge, scan)

        tests = scan.get("tests", [])
        total_tests = len(tests)

        if total_tests == 0:
            st.warning("No test cases found in selected scan pack")
            st.stop()

        progress_bar = st.progress(0)
        status_text = st.empty()

        results = []

        with st.spinner(f"Running {total_tests} security tests..."):
            for idx, verdict in enumerate(agent.run(evaluate_test), start=1):
                results.append(verdict)

                progress = int((idx / total_tests) * 100)
                progress_bar.progress(progress)

                status_text.markdown(
                    f"**Running test {idx}/{total_tests}** → `{verdict['id']}`"
                )

        progress_bar.progress(100)
        status_text.markdown("✅ **Scan completed successfully**")

        st.session_state["scan_results"] = results
        st.session_state["scan_name"] = scan.get("scan_name")
        st.session_state["last_scan_file"] = save_scan_result(
            st.session_state["scan_name"], cfg, results
        )

        st.success(f"Scan completed: {selected_scan_name}")


    # if st.button("▶ Run Scan"):
    #     agent = ScanAgent(llm, scan)

    #     with st.spinner("Running security tests..."):
    #         results = agent.run(evaluate_test)

    #     st.session_state["scan_results"] = results
    #     st.session_state["scan_name"] = selected_scan_name
    #     st.session_state["last_scan_file"] = save_scan_result(
    #         selected_scan_name,
    #         cfg,
    #         results
    #     )

    #     st.success(f"Scan completed: {selected_scan_name}")

# if mode == "🧪 Test Scenarios":
#     st.subheader("🧪 Security Test Scenarios")

#     uploaded_scan = st.file_uploader(
#         "Upload Scan Pack (JSON)",
#         type="json",
#         help="Upload custom scan pack or use default OWASP scan"
#     )

#     scan = (
#         json.load(uploaded_scan)
#         if uploaded_scan
#         else load_scan_from_path(DEFAULT_SCAN_FILE)
#     )

#     # lang = st.selectbox("Language", ["en", "hi"], index=0)

#     if st.button("▶ Run Scan"):
#         agent = ScanAgent(llm, scan)

#         with st.spinner("Running security tests..."):
#             # results = agent.run(evaluate_test, lang)

#         st.session_state["scan_results"] = results
#         st.session_state["scan_name"] = scan.get("scan_name", "LLM Security Scan")
#         st.session_state["last_scan_file"] = save_scan_result(
#             st.session_state["scan_name"], cfg, results
#         )

#         st.success("Scan completed successfully")

    # ---------- Scan Execution Details ----------
    st.markdown("## 🧾 Scan Execution Details")

    if isinstance(st.session_state["scan_results"], list) and len(st.session_state["scan_results"]) > 0:
        for idx, r in enumerate(st.session_state["scan_results"], 1):
            st.markdown(f"### {idx}. {r['id']} – {r['category']}")
            st.markdown(f"**Severity:** `{r['severity']}`")
            st.markdown(
                f"**Status:** {'❌ Vulnerable' if r['vulnerable'] else '✅ Safe'}"
            )
            st.markdown(
                f"**Final Verdict:** {'❌ Vulnerable' if r['vulnerable'] else '✅ Safe'}"
            )
            st.markdown(f"**Decision Source:** `{r['decision_source']}`")
            st.markdown(f"**Reason:** {r['reason']}")

            with st.expander("📤 Prompt Sent"):
                st.code(r["prompt"])

            with st.expander("📥 LLM Response"):
                st.markdown(r["response"])
            with st.expander("🤖 Judge LLM Analysis"):
                st.markdown(r.get("judge_reason", "N/A"))
            with st.expander("🔑 Keyword Signal"):
                st.markdown(
                    "Matched keywords" if r.get("keyword_vulnerable") else "No keyword match"
                )

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
        st.stop()

    PAGE_SIZE = 8
    total_scans = len(files)
    total_pages = (total_scans + PAGE_SIZE - 1) // PAGE_SIZE

    if "scan_history_page" not in st.session_state:
        st.session_state["scan_history_page"] = 1

    page = st.session_state["scan_history_page"]
    page = max(1, min(page, total_pages))

    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    page_files = files[start:end]

    # ---- Header Row ----
    # h1, h2, h3, h4, h5 = st.columns([3, 3, 2, 1, 1])
    # h1.markdown("**Timestamp**")
    # h2.markdown("**Scan Name**")
    # h3.markdown("**Model**")
    # h4.markdown("**Vulns**")
    # h5.markdown("")

    with st.container():
        st.markdown('<div class="sticky-header">', unsafe_allow_html=True)
        h1, h2, h3, h4, h5, h6 = st.columns([2.3, 3, 2, 1.2, 2.2, 0.8])
        h1.caption("Timestamp")
        h2.caption("Scan Name")
        h3.caption("Model")
        h4.caption("Vulns")
        h5.caption("Compliance Gaps")
        h6.caption("")
        st.markdown('</div>', unsafe_allow_html=True)

    # st.divider()

    for idx, f in enumerate(page_files):

        data = load_scan_file(f)
        results = data["results"]
        vuln_count = sum(
            1 for r in results
            if r.get("vulnerable") is True
        )

        severity, sev_class = calc_severity(results)
        gaps = compliance_gaps(results)

        c1, c2, c3, c4, c5, c6 = st.columns([2.3, 3, 2, 1.2, 2.2, 0.8])

        # Timestamp
        c1.caption(data["executed_at"])

        # Clickable Scan Name → Dashboard
        c2.markdown(f"**{data['scan_name']}**")

        # Model
        c3.caption(data["llm"]["model"])

        # vuln_count = sum(
        #     1 for r in results
        #     if r.get("is_vulnerable") is True
        #     or r.get("verdict", "").lower() == "fail"
        # )

        badge_class = "badge-vuln-red" if vuln_count > 0 else "badge-vuln-green"
        badge_text = f"{vuln_count} Vulns" if vuln_count > 0 else "0 Vulns"

        c4.markdown(
            f"<span class='badge {badge_class}'>{badge_text}</span>",
            unsafe_allow_html=True
        )

        # # 🔥 Vuln Count (NEW)
        # if vuln_count > 0:
        #     c4.markdown(
        #         f'<span class="badge badge-vuln-red">{vuln_count} Vulns</span>',
        #         unsafe_allow_html=True
        #     )
        # else:
        #     c4.markdown(
        #         '<span class="badge badge-vuln-green">0 Vulns</span>',
        #         unsafe_allow_html=True
        #     )

        # Severity
        # c5.markdown(
        #     f'<span class="badge {sev_class}">{severity}</span>',
        #     unsafe_allow_html=True
        # )

        # Compliance Gaps
        if gaps:
            for g in sorted(gaps):
                c5.markdown(f"<span class='badge badge-gap'>{g}</span>", unsafe_allow_html=True)
        else:
            c5.markdown("<span class='badge badge-safe'>No Gaps</span>", unsafe_allow_html=True)

        # Actions (⋮ SAME ROW)
        with c6:
            with st.popover("⋮"):

                # 1️⃣ Load Dashboard
                if st.button("📊 Load to Dashboard", key=f"ld_{idx}"):
                    st.session_state["scan_results"] = results
                    st.session_state["scan_name"] = data["scan_name"]
                    st.session_state["mode"] = "Dashboard"
                    st.rerun()

                # 2️⃣ Generate PDF (on demand)
                pdf_path = generate_pdf_report(
                    data["scan_name"],
                    load_cfg(),
                    results
                )

                # 3️⃣ Download PDF
                with open(pdf_path, "rb") as pdf:
                    st.download_button(
                        label="📄 Download PDF",
                        data=pdf,
                        file_name=os.path.basename(pdf_path),
                        mime="application/pdf",
                        key=f"pdf_{idx}"
                    )

                # 4️⃣ Download JSON
                with open(f, "rb") as jf:
                    st.download_button(
                        label="📦 Download JSON",
                        data=jf,
                        file_name=os.path.basename(f),
                        mime="application/json",
                        key=f"json_{idx}"
                    )

                # 5️⃣ Delete Scan
                # if st.button("🗑️ Delete Scan", key=f"del_{idx}"):
                #     if st.checkbox("Confirm delete", key=f"confirm_{idx}"):
                #         try:
                #             os.remove(f)
                #             st.success("Scan deleted successfully")
                #             st.rerun()
                #         except Exception as e:
                #             st.error(f"Failed to delete scan: {e}")


        st.divider()




        # with c1:
        #     st.markdown(
        #         f"<div class='scan-timestamp'>{data['executed_at']}</div>",
        #         unsafe_allow_html=True
        #     )

        # with c2:
        #     st.markdown(
        #         f"<div class='scan-name'>{data['scan_name']}</div>",
        #         unsafe_allow_html=True
        #     )

        # with c3:
        #     st.markdown(
        #         f"<div class='scan-model'>{data['llm']['model']}</div>",
        #         unsafe_allow_html=True
        #     )

        # with c4:
        #     st.markdown(
        #         f"<span class='badge {badge_class}'>{badge_text}</span>",
        #         unsafe_allow_html=True
        #     )

        # with c5:
        #     with st.popover("⋮"):
        #         if st.button("📊 Load to Dashboard", key=f"load_{idx}"):
        #             st.session_state["scan_results"] = data["results"]
        #             st.session_state["scan_name"] = data["scan_name"]
        #             st.switch_page("📊 Dashboard")

        #         pdf_path = generate_pdf_report(
        #             data["scan_name"],
        #             load_cfg(),
        #             data["results"]
        #         )

        #         with open(pdf_path, "rb") as pdf:
        #             st.download_button(
        #                 "📄 Download PDF",
        #                 pdf,
        #                 file_name=pdf_path.split("/")[-1],
        #                 mime="application/pdf",
        #                 key=f"pdf_{idx}"
        #             )

        #         with open(f, "rb") as jf:
        #             st.download_button(
        #                 "📦 Download JSON",
        #                 jf,
        #                 file_name=f.split("/")[-1],
        #                 mime="application/json",
        #                 key=f"json_{idx}"
        #             )

        # st.markdown("<div class='scan-row'></div>", unsafe_allow_html=True)

        # st.divider()

    # ---- Pagination ----
    p1, p2, p3 = st.columns([1, 2, 1])

    with p1:
        if st.button("⬅ Previous", disabled=(page <= 1)):
            st.session_state["scan_history_page"] -= 1
            st.rerun()

    with p2:
        st.markdown(
            f"<div style='text-align:center;'>Page <b>{page}</b> of <b>{total_pages}</b></div>",
            unsafe_allow_html=True
        )

    with p3:
        if st.button("Next ➡", disabled=(page >= total_pages)):
            st.session_state["scan_history_page"] += 1
            st.rerun()


# if mode == "📂 Scan History":
#     st.subheader("📂 Scan History")

#     files = list_scan_files()

#     if not files:
#         st.info("No scan history found")
#         st.stop()

#     PAGE_SIZE = 8
#     total_scans = len(files)
#     total_pages = (total_scans + PAGE_SIZE - 1) // PAGE_SIZE

#     # Current page
#     page = st.session_state["scan_history_page"]

#     # Bounds check
#     page = max(1, min(page, total_pages))
#     st.session_state["scan_history_page"] = page

#     start = (page - 1) * PAGE_SIZE
#     end = start + PAGE_SIZE

#     page_files = files[start:end]

#     rows = []
#     for f in page_files:
#         data = load_scan_file(f)
#         if not data:
#             continue

#         rows.append({
#             "Timestamp": data["executed_at"],
#             "Scan Name": data["scan_name"],
#             "Model": data["llm"]["model"],
#             "Vulnerabilities": sum(
#                 1 for r in data["results"]
#                 if r.get("vulnerable") is True
#                 or r.get("severity", "").lower() in ["medium", "high", "critical"]
#             ),
#             "File": f
#         })

#     df = pd.DataFrame(rows)

#     if df.empty:
#         st.info("No valid scan records on this page")
#         st.stop()

#     st.dataframe(df.drop(columns=["File"]), width="stretch")

#     # -------- Pagination Controls --------
#     col1, col2, col3 = st.columns([1, 2, 1])

#     with col1:
#         if st.button("⬅ Previous", disabled=(page <= 1)):
#             st.session_state["scan_history_page"] -= 1
#             st.rerun()

#     with col2:
#         st.markdown(
#             f"<div style='text-align:center;'>Page <b>{page}</b> of <b>{total_pages}</b></div>",
#             unsafe_allow_html=True
#         )

#     with col3:
#         if st.button("Next ➡", disabled=(page >= total_pages)):
#             st.session_state["scan_history_page"] += 1
#             st.rerun()

#     # -------- Load scan into dashboard --------
#     selected_ts = st.selectbox(
#         "Select scan to load into Dashboard",
#         df["Timestamp"].tolist()
#     )

#     if st.button("🔄 Load Selected Scan"):
#         file_path = df[df["Timestamp"] == selected_ts]["File"].values[0]
#         data = load_scan_file(file_path)

#         st.session_state["scan_results"] = data["results"]
#         st.session_state["scan_name"] = data["scan_name"]

#         st.success("Scan loaded into Dashboard")


# if mode == "📂 Scan History":
#     st.subheader("📂 Scan History")

#     files = list_scan_files()
#     if not files:
#         st.info("No scan history found")
#     else:
#         rows = []
#         for f in files:
#             data = load_scan_file(f)
#             if not data:
#                 continue
#             rows.append({
#                 "Timestamp": data["executed_at"],
#                 "Scan Name": data["scan_name"],
#                 "Model": data["llm"]["model"],
#                 "Vulnerabilities": sum(
#                     1 for r in data["results"]
#                     if r.get("vulnerable") is True
#                     or r.get("severity", "").lower() in ["medium", "high", "critical"]
#                 ),
#                 "File": f
#             })

#         df = pd.DataFrame(rows)
#         st.dataframe(df.drop(columns=["File"]), width="stretch")

#         selected_ts = st.selectbox(
#             "Select scan to load into Dashboard",
#             df["Timestamp"].tolist()
#         )

#         if st.button("🔄 Load Selected Scan"):
#             file_path = df[df["Timestamp"] == selected_ts]["File"].values[0]
#             data = load_scan_file(file_path)
#             st.session_state["scan_results"] = data["results"]
#             st.session_state["scan_name"] = data["scan_name"]
#             st.success("Scan loaded into Dashboard")
