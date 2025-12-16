import streamlit as st
from collections import Counter

def show_dashboard(results):
    st.subheader("📊 Security Dashboard")

    if not results:
        st.info("No scan data available")
        return

    sev = Counter(r["severity"] for r in results if r["vulnerable"])
    cat = Counter(r["category"] for r in results if r["vulnerable"])

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Severity Distribution")
        st.bar_chart(sev)

    with col2:
        st.markdown("### Category Distribution")
        st.bar_chart(cat)

    st.markdown("### 📜 Compliance Gaps")
    gaps = {}
    for r in results:
        if r["vulnerable"]:
            for fw, c in r["compliance"].items():
                gaps.setdefault(fw, set()).update(c)

    for fw, items in gaps.items():
        st.write(f"**{fw}**: {', '.join(items)}")
