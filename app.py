import re
import streamlit as st
from urllib.parse import urlparse
from datetime import datetime
from io import BytesIO
# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)
st.title("🛡️ CyberShield AI")
col1, col2, col3 = st.columns(3)

with col1:
    st.info("🔎 URL Scanner\n\nChecks suspicious URL indicators.")

with col2:
    st.info("📩 Phishing Checker\n\nChecks messages for warning patterns.")

with col3:
    st.info("🛡️ Safety Center\n\nProvides practical cyber safety tips.")


st.subheader("Your Smart Cyber Security Assistant")
st.caption("Identify suspicious URL indicators, check messages, and learn safer online habits.")


# ---------------- DESIGN ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #07111f, #101d35);
    color: #ffffff;
}
h1, h2, h3 {
    color: #38bdf8;
}
div[data-testid="stMetric"] {
    background: #14243b;
    border: 1px solid #294768;
    padding: 18px;
    border-radius: 12px;
}
.stButton > button {
    background-color: #0284c7;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 10px 20px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ CyberShield AI")
st.subheader("Smart Cyber Security Assistant")
st.caption("Detect warning signs. Understand risks. Stay protected.")

st.info(
    "Educational demo: Results are heuristic indicators, "
    "not proof that a URL or message is safe or malicious."
)
def create_pdf_report(scan_history):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("CyberShield AI", styles["Title"]))
    story.append(Paragraph(
        "Cyber Security Scan Report",
        styles["Heading2"]
    ))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(
        f"Report Generated: {datetime.now().strftime('%d-%m-%Y %I:%M %p')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(
        f"Total Scans: {len(scan_history)}",
        styles["Heading3"]
    ))
    story.append(Spacer(1, 0.2 * inch))

    table_data = [[
        "Type", "Input", "Result", "Risk Level", "Date & Time"
    ]]

    for item in scan_history:
        table_data.append([
            str(item.get("type", ""))[:20],
            str(item.get("input", ""))[:45],
            str(item.get("result", ""))[:45],
            str(item.get("risk", "Not recorded"))[:20],
            str(item.get("time", "Not recorded"))[:25]
        ])

    table = Table(
        table_data,
        colWidths=[
            0.65 * inch, 1.5 * inch, 1.5 * inch,
            0.9 * inch, 1.3 * inch
        ],
        repeatRows=1
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123456")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph(
        "Note: This is an educational, rule-based prototype. "
        "Results are indicators, not a guarantee that a URL or message "
        "is safe or malicious.",
        styles["Normal"]
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


# ---------------- URL ANALYZER ----------------

def analyze_url(raw_url):
    url = raw_url.strip()
    findings = []
    score = 0
    if not url:
        return 0, ["Please enter a URL."]

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        domain = host.lower()
    except ValueError:
        return 100, ["URL could not be parsed."]
    if not host or "." not in host:
        findings.append("The hostname looks incomplete or unusual.")
        score += 25

    if parsed.scheme != "https":
        findings.append("The URL does not use HTTPS.")
        score += 10

    if parsed.username or parsed.password:
        findings.append("The URL contains user-info before the hostname.")
        score += 30

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        findings.append("The hostname is an IP address.")
        score += 20

    if len(url) > 100:
        findings.append("The URL is unusually long.")
        score += 10

    if "@" in url:
        findings.append("The URL contains '@', which can be misleading.")
        score += 15

    if url.count(".") >= 4:
        findings.append("The URL has many dot-separated parts.")
        score += 10

    suspicious_words = [
        "login", "verify", "account", "password",
        "banking", "wallet", "free", "prize",
        "urgent", "secure-update"
    ]

    matched = [word for word in suspicious_words if word in url.lower()]

    if matched:
        findings.append(
            "Potentially suspicious terms: " + ", ".join(matched)
        )
        score += min(20, len(matched) * 5)

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"]

    if domain in shorteners:
        findings.append("The URL shortener hides the final destination.")
        score += 20

    score = min(score, 100)

    if not findings:
        findings.append(
            "No configured warning signs detected. This does not prove the URL is safe."
        )

    return score, findings

def risk_level(score):
    if score >= 50:
        return "HIGH", "🔴"
    elif score >= 25:
        return "MEDIUM", "🟠"
    return "LOW INDICATOR", "🟢"


# ---------------- PHISHING ANALYZER ----------------
def analyze_message(message):
    patterns = {
        "Urgent or threatening language": [
            r"\burgent\b", r"\bimmediately\b",
            r"\baccount.*suspend", r"\bwithin \d+ hours\b"
        ],
        "Requests for credentials or sensitive data": [
            r"\bpassword\b", r"\botp\b",
            r"\bpin\b", r"\bverify your account\b",
            r"\bcard details\b"
        ],
        "Prize or unexpected reward claims": [
            r"\byou have won\b", r"\bclaim your prize\b",
            r"\bfree gift\b", r"\blottery winner\b"
        ],
        "Suspicious payment requests": [
            r"\bpay a fee\b", r"\btransfer money\b",
            r"\bgift card\b", r"\bpayment required\b"
        ],
        "Links included in the message": [
            r"https?://", r"\bwww\."
        ]
    }

    findings = []

    for label, expressions in patterns.items():
        if any(re.search(pattern, message, re.I) for pattern in expressions):
            findings.append(label)

    return findings


# ---------------- DASHBOARD ----------------
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("URL Scanner", "Active")

with col2:
    st.metric("Message Analyzer", "Active")

with col3:
    st.metric("Security Tips", "Available")

st.divider()

# ---------------- TABS ----------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 URL Scanner",
    "🎣 Phishing Message Checker",
    "🛡️ Safety Center",
    "📜 Scan History"
])
if "url_scan_count" not in st.session_state:
    st.session_state.url_scan_count = 0
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "message_scan_count" not in st.session_state:
    st.session_state.message_scan_count = 0

def count_url_scan():
    st.session_state.url_scan_count += 1
def count_message_scan():
    st.session_state.message_scan_count += 1

col1, col2, col3 = st.columns(3)

col1.metric("🔎 URL Scans", st.session_state.url_scan_count)
col2.metric("📩 Message Scans", st.session_state.message_scan_count)

col3.metric(
"🛡️ Total Scans",
st.session_state.url_scan_count + st.session_state.message_scan_count
)


# URL TAB
with tab1:
    st.header("Suspicious URL Analyzer")
    st.write("Enter a URL to inspect basic warning signs.")

    url_input = st.text_input(
        "Website URL",
        placeholder="https://example.com"
    )

if st.button("Analyze URL", key="url_button", on_click=count_url_scan):
        if not url_input.strip():
            st.warning("Please enter a URL first.")
        else:
            score, findings = analyze_url(url_input)
            st.session_state.scan_history.append({
    "type": "URL",
    "input": url_input.strip(),
    "result": f"Risk Score: {score}/100",
    "time": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p"),
    "risk": risk_level(score)[0]
})
            display_url = url_input.strip()
            if "://" not in display_url:
                display_url = "https://" + display_url
            domain = urlparse(display_url).hostname
            st.write("🌐 **Domain:**", domain or "Unable to identify domain")
            level, icon = risk_level(score)

            st.subheader("Analysis Results")

            c1, c2 = st.columns(2)

            with c1:
                st.metric("Heuristic Risk Score", f"{score}/100")

            with c2:
                st.metric("Risk Indicator", f"{icon} {level}")

            st.progress(score / 100)

            for finding in findings:
                st.write("•", finding)

            st.warning(
                "This score is based on simple rules, not a trained AI "
                "model or a live threat-intelligence database. "
                "A low score does not mean a website is safe."
            )
            report = (
                f"CyberShield AI - URL Analysis Report\n"
                f"URL: {url_input}\n"
                f"Risk Score: {score}/100\n"
                f"Risk Indicator: {level}\n\n"
                "Findings:\n"
                + "\n".join(f"- {finding}" for finding in findings)
                + "\n\nNote: This report uses rule-based analysis. "
                "It does not guarantee that a URL is safe or malicious."
            )

            st.download_button(
                label="📥 Download URL Report",
                data=report,
                file_name="cybershield_url_report.txt",
                mime="text/plain",
                key="download_url_report"
            )

        pdf_data = create_pdf_report(st.session_state.scan_history)

        st.download_button(
            label="📄 Download Professional PDF Report",
            data=pdf_data,
            file_name="CyberShield_AI_Report.pdf",
            mime="application/pdf",
            key="download_pdf_report"
        )


# MESSAGE TAB
# MESSAGE TAB

with tab2:
    st.header("Phishing Message Analyzer")
    st.write("Paste a suspicious SMS, email or message.")

message_input = st.text_area(
    "Message",
    placeholder=(
        "Example: Your account will be suspended. "
        "Verify your password immediately."
    ),
    height=150
)

if st.button("Analyze Message", key="message_button", on_click=count_message_scan):
    if not message_input.strip():
        st.warning("Please paste a message first.")
    else:
        findings = analyze_message(message_input)

        st.session_state.scan_history.append({
            "type": "Message",
            "input": message_input.strip()[:100],
            "result": "Potential phishing signs found" if findings else "No common warning signs detected",
            "time": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p"),
            "risk": "HIGH" if findings else "LOW INDICATOR"
        })

        if findings:
            st.error("⚠️ Potential phishing warning signs found.")

            for finding in findings:
                st.write("•", finding)

            st.write(
                "**What to do:** Avoid clicking unexpected links "
                "or sharing passwords, PINs or OTPs."
            )
        else:
            st.success("No common phishing warning signs detected.")
        report_text = (
            "CyberShield AI - Phishing Message Analysis Report\n"
            f"Message Analyzed: {message_input}\n\n"
            "Warning Signs:\n"
            + (
                "\n".join(f"- {finding}" for finding in findings)
                if findings
                else "No configured warning patterns detected."
            )
            + "\n\nNote: This tool uses rule-based analysis. "
            "It cannot guarantee that a message is safe or malicious."
        )

        st.download_button(
            label="📥 Download Phishing Report",
            data=report_text,
            file_name="cybershield_phishing_report.txt",
            mime="text/plain",
            key="download_phishing_report"
        )


# SAFETY TAB
with tab3:
    st.header("Cyber Safety Center")

    tips = [
        "Never share your OTP, password or banking PIN.",
        "Check the exact domain before opening a website.",
        "Do not trust messages only because they create urgency.",
        "Enable multi-factor authentication on important accounts.",
        "Use unique passwords and a reputable password manager.",
        "Confirm payment requests through a separate trusted channel.",
        "Keep your operating system, browser and apps updated.",
        "If a message seems suspicious, contact the organization "
        "through its official website or app."
    ]

    for i, tip in enumerate(tips, start=1):
        st.write(f"**{i}.** {tip}")
# SCAN HISTORY TAB
with tab4:
    st.header("📜 Scan History")

    if st.session_state.scan_history:
        for item in reversed(st.session_state.scan_history):
            st.write(f"**Scan Type:** {item['type']}")
            st.write(f"**Input:** {item['input']}")
            st.write(f"**Result:** {item['result']}")

            if "time" in item:
                st.write(f"**Date & Time:** {item['time']}")

            if "risk" in item:
                st.write(f"**Risk Level:** {item['risk']}")

            st.divider()

        report_lines = [
            "CyberShield AI - Scan History Report",
            "=" * 40,
            ""
        ]

        for item in reversed(st.session_state.scan_history):
            report_lines.extend([
                f"Scan Type: {item['type']}",
                f"Input: {item['input']}",
                f"Result: {item['result']}",
                f"Date & Time: {item.get('time', 'Not recorded')}",
                f"Risk Level: {item.get('risk', 'Not recorded')}",
                "-" * 40,
                ""
            ])

        report_text = "\n".join(report_lines)

        st.download_button(
            label="📥 Download Scan Report",
            data=report_text,
            file_name="CyberShield_AI_Scan_Report.txt",
            mime="text/plain"
        )
    else:
        st.info("No scans yet. Analyze a URL or message first.")


    if not st.session_state.scan_history:
        st.info("No scans yet. Analyze a URL or message to see history here.")
    else:
        for item in reversed(st.session_state.scan_history):
            with st.expander(f"🔎 {item['type']} Scan"):
                st.write("**Input:**", item["input"])
                st.write("**Result:**", item["result"])

        if st.button("🗑️ Clear Scan History"):
            st.session_state.scan_history.clear()
            st.rerun()
st.divider()

st.caption(
    "CyberShield AI | Student Hackathon Prototype | "
    "Rule-based educational analysis"
)
# RISK ANALYTICS DASHBOARD

st.divider()
st.header("📊 Risk Analytics Dashboard")

high_count = sum(
1 for item in st.session_state.scan_history
if item.get("risk", "").upper() == "HIGH"
)

medium_count = sum(
1 for item in st.session_state.scan_history
if item.get("risk", "").upper() == "MEDIUM"
)

low_count = sum(
1 for item in st.session_state.scan_history
if item.get("risk", "").upper() in ["LOW", "LOW INDICATOR"]
)

col_a, col_b, col_c = st.columns(3)

col_a.metric("🔴 High Risk", high_count)
col_b.metric("🟠 Medium Risk", medium_count)
col_c.metric("🟢 Low Risk", low_count)

st.subheader("📊 Risk Distribution")

risk_chart_data = {
    "Risk Level": ["HIGH", "MEDIUM", "LOW"],
    "Scans": [high_count, medium_count, low_count]
}

import pandas as pd

risk_chart_df = pd.DataFrame(risk_chart_data)
risk_chart_df = risk_chart_df.set_index("Risk Level")

st.bar_chart(risk_chart_df)
# RECENT SCAN SUMMARY

st.divider()
st.header("🕒 Recent Scan Summary")

if st.session_state.scan_history:
    recent_scans = st.session_state.scan_history[-5:][::-1]

    recent_data = []

    for item in recent_scans:
        recent_data.append({
            "Scan Type": item.get("type", "Unknown"),
            "Input": item.get("input", ""),
            "Result": item.get("result", ""),
            "Risk Level": item.get("risk", "Not recorded"),
            "Date & Time": item.get("time", "Not recorded")
        })

    recent_df = pd.DataFrame(recent_data)

    st.dataframe(
        recent_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No recent scans available. Analyze a URL or message first.")
# SECURITY SCORE DASHBOARD

st.divider()
st.header("🛡️ Security Score Dashboard")

total_scans = len(st.session_state.scan_history)

high_risk_scans = sum(
1 for item in st.session_state.scan_history
if item.get("risk", "").upper() == "HIGH"
)

medium_risk_scans = sum(
1 for item in st.session_state.scan_history
if item.get("risk", "").upper() == "MEDIUM"
)

if total_scans == 0:
    security_score = 100
else:
    security_score = max(
        0,
        100 - int(
            (high_risk_scans * 30 + medium_risk_scans * 15)
            / total_scans
        )
    )

st.metric("🔐 Security Score", f"{security_score}/100")

if security_score >= 80:
    st.success("Good score! Continue following safe cyber practices.")
elif security_score >= 50:
    st.warning("Moderate score. Review the detected risks and safety tips.")
else:
    st.error("Low score. Review the warnings and take precautions.")

st.caption(
"Educational estimate based on recorded scan results, "
"not a guarantee of device or account security."
)


