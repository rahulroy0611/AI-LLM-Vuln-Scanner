import streamlit as st
from collections import Counter

def show_dashboard(results):
    st.subheader("📊 Security Dashboard")

    if not results:
        st.warning("No scan results to display")
        return

    severity_counts = Counter(
        r["severity"] for r in results if r["vulnerable"]
    )
    category_counts = Counter(
        r["category"] for r in results if r["vulnerable"]
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🔥 Severity Distribution")
        if severity_counts:
            st.bar_chart(severity_counts)
        else:
            st.info("No vulnerabilities found")

    with col2:
        st.markdown("### 🧩 Category Distribution")
        if category_counts:
            st.bar_chart(category_counts)
        else:
            st.info("No vulnerable categories")

    # Compliance gaps
    st.markdown("### 📜 Compliance Gaps")
    gaps = {}
    for r in results:
        if r["vulnerable"]:
            for fw, items in r["compliance"].items():
                gaps.setdefault(fw, set()).update(items)

    if gaps:
        for fw, items in gaps.items():
            st.write(f"**{fw}**: {', '.join(items)}")
    else:
        st.success("No compliance gaps detected")
