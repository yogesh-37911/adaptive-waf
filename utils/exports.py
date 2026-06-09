"""
utils/exports.py — CSV and PDF report generators.
"""

import io
import csv
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CSV Export
# ─────────────────────────────────────────────────────────────────────────────

def export_logs_csv(logs: list) -> bytes:
    """Convert request log rows to CSV bytes."""
    output = io.StringIO()
    if not logs:
        return b"No data"
    writer = csv.DictWriter(output, fieldnames=logs[0].keys())
    writer.writeheader()
    writer.writerows(logs)
    return output.getvalue().encode("utf-8")


def export_attacks_csv(attacks: list) -> bytes:
    """Convert attack event rows to CSV bytes."""
    output = io.StringIO()
    if not attacks:
        return b"No data"
    writer = csv.DictWriter(output, fieldnames=attacks[0].keys())
    writer.writeheader()
    writer.writerows(attacks)
    return output.getvalue().encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report using fpdf2
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(stats: dict, attacks: list, rl_summary: dict,
                        top_ips: list, reports_dir: str) -> str:
    """
    Generate a professional PDF security report.
    Returns the file path of the created PDF.
    """
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError:
        logger.error("fpdf2 not installed - pip install fpdf2")
        return ""

    os.makedirs(reports_dir, exist_ok=True)
    filename = f"waf_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(reports_dir, filename)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Cover Section ────────────────────────────────────────────────────────
    pdf.set_fill_color(15, 15, 30)
    pdf.rect(0, 0, 210, 50, "F")
    pdf.set_text_color(0, 255, 136)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(10, 10)
    pdf.cell(0, 10, "ADAPTIVE WAF SECURITY REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(180, 180, 200)
    pdf.set_x(10)
    pdf.cell(0, 8, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    pdf.set_xy(10, 55)

    # ── Summary Table ────────────────────────────────────────────────────────
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)

    summary_rows = [
        ("Total Requests",    str(stats.get("total", 0))),
        ("Blocked Requests",  str(stats.get("blocked", 0))),
        ("Allowed Requests",  str(stats.get("allowed", 0))),
        ("Attacks Detected",  str(stats.get("attacks", 0))),
        ("False Positives",   str(stats.get("false_positives", 0))),
        ("RL Training Steps", str(rl_summary.get("steps", 0))),
        ("Avg RL Reward",     f"{rl_summary.get('avg_reward', 0.0):.4f}"),
        ("Detection Accuracy",f"{_calc_accuracy(stats):.1f}%"),
    ]

    for label, value in summary_rows:
        pdf.set_fill_color(240, 240, 250)
        pdf.cell(90, 8, label, border=1, fill=True)
        pdf.cell(90, 8, value, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(8)

    # ── Top Attacking IPs ────────────────────────────────────────────────────
    if top_ips:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Top Suspicious IPs", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(220, 30, 60)
        pdf.set_text_color(255, 255, 255)
        for col, w in [("IP Address", 60), ("Total Requests", 50), ("Blocked", 40), ("Avg Score", 40)]:
            pdf.cell(w, 8, col, border=1, fill=True)
        pdf.ln()

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 10)
        for ip in top_ips[:10]:
            pdf.set_fill_color(250, 250, 255)
            pdf.cell(60, 7, str(ip.get("ip_address", "")),    border=1, fill=True)
            pdf.cell(50, 7, str(ip.get("total", 0)),           border=1, fill=True)
            pdf.cell(40, 7, str(ip.get("blocked", 0)),         border=1, fill=True)
            pdf.cell(40, 7, f"{ip.get('avg_score', 0.0):.3f}", border=1, fill=True)
            pdf.ln()

    pdf.ln(6)

    # ── Recent Attacks ────────────────────────────────────────────────────────
    if attacks:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Recent Attack Events (last 20)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(30, 30, 60)
        pdf.set_text_color(255, 255, 255)
        for col, w in [("Timestamp", 42), ("IP", 35), ("Type", 30), ("Score", 22), ("Blocked", 22), ("Severity", 25)]:
            pdf.cell(w, 8, col, border=1, fill=True)
        pdf.ln()

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)
        for atk in attacks[:20]:
            pdf.set_fill_color(252, 252, 255)
            ts  = str(atk.get("timestamp", ""))[:16]
            ip  = str(atk.get("ip_address", ""))[:14]
            typ = str(atk.get("attack_type", ""))[:12]
            sc  = f"{atk.get('threat_score', 0.0):.2f}"
            blk = "YES" if atk.get("blocked") else "NO"
            sev = str(atk.get("severity", ""))
            for val, w in [(ts,42),(ip,35),(typ,30),(sc,22),(blk,22),(sev,25)]:
                pdf.cell(w, 6, val, border=1, fill=True)
            pdf.ln()

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 140)
    pdf.cell(0, 6, "Adaptive WAF using Reinforcement Learning | Confidential Security Report")

    pdf.output(filepath)
    logger.info(f"PDF report generated: {filepath}")
    return filepath


def _calc_accuracy(stats: dict) -> float:
    total = stats.get("total", 0)
    if total == 0:
        return 0.0
    tp = stats.get("attacks", 0)
    fp = stats.get("false_positives", 0)
    return ((total - fp) / total) * 100
