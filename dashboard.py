import streamlit as st
import pandas as pd
import altair as alt
from collections import Counter

# Severity → Color mapping
SEVERITY_COLORS = {
    "Critical": "#D32F2F",  # Red
    "High": "#F57C00",      # Orange
    "Medium": "#FBC02D",    # Yellow
    "Low": "#388E3C"        # Green
}

def show_dashboard(results):
    st.subheader("📊 Security Dashboard")

    if not results:
        st.warning("No scan results to display")
        return

    # ---------------- Severity Distribution ----------------
    severity_counts = Counter(
        r["severity"] for r in results
        if r.get("vulnerable") is True
        or r.get("severity", "").lower() in ["medium", "high", "critical"]
    )

    if severity_counts:
        sev_df = pd.DataFrame({
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        })

        chart_sev = alt.Chart(sev_df).mark_bar().encode(
            x=alt.X("Severity:N", sort=["Critical", "High", "Medium", "Low"]),
            y="Count:Q",
            color=alt.Color(
                "Severity:N",
                scale=alt.Scale(domain=list(SEVERITY_COLORS.keys()),
                                range=list(SEVERITY_COLORS.values())),
                legend=alt.Legend(title="Severity")
            ),
            tooltip=["Severity", "Count"]
        ).properties(
            title="🔥 Severity Distribution",
            height=300
        )

        st.altair_chart(chart_sev, width="stretch")
    else:
        st.info("No vulnerabilities detected")

    # ---------------- Category Distribution ----------------
    category_counts = Counter(
        r["category"] for r in results
        if r.get("vulnerable") is True
        or r.get("severity", "").lower() in ["medium", "high", "critical"]
    )

    if category_counts:
        cat_df = pd.DataFrame({
            "Category": list(category_counts.keys()),
            "Count": list(category_counts.values())
        })

        chart_cat = alt.Chart(cat_df).mark_bar(color="#64B5F6").encode(
            x=alt.X("Category:N", sort="-y"),
            y="Count:Q",
            tooltip=["Category", "Count"]
        ).properties(
            title="🧩 Category Distribution",
            height=300
        )

        st.altair_chart(chart_cat, width="stretch")

    # ---------------- Compliance Gaps ----------------
    st.markdown("### 📜 Compliance Gaps")

    gaps = {}
    for r in results:
        if r.get("vulnerable") is True or r.get("severity", "").lower() in ["medium", "high", "critical"]:
            for fw, items in r.get("compliance", {}).items():
                gaps.setdefault(fw, set()).update(items)

    if gaps:
        for fw, items in gaps.items():
            st.write(f"**{fw}**: {', '.join(sorted(items))}")
    else:
        st.success("No compliance gaps detected")
