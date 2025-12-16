from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from datetime import datetime
import os

def generate_pdf_report(scan_name, cfg, results):
    os.makedirs("reports", exist_ok=True)
    file = f"reports/{scan_name.replace(' ', '_')}_Executive_Report.pdf"

    doc = SimpleDocTemplate(file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("AI LLM Security Assessment – Executive Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Model: {cfg['model']}", styles["Normal"]))
    story.append(Paragraph(f"Executed: {datetime.utcnow()}", styles["Normal"]))
    story.append(Spacer(1, 12))

    table = [["ID", "Category", "Severity", "Status"]]
    for r in results:
        table.append([
            r["id"],
            r["category"],
            r["severity"],
            "Vulnerable" if r["vulnerable"] else "Safe"
        ])

    story.append(Table(table))
    doc.build(story)
    return file
