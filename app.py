import streamlit as st
import re
from datetime import datetime

# =========================
# Page Configuration
# =========================

st.set_page_config(
    page_title="VulnGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ VulnGuard")
st.subheader("Malware, Vulnerability & Attack Detection Tool")

st.write(
    "Detect suspicious activities, attack indicators, IP addresses, "
    "IOCs and malware-related behaviour from security logs."
)

# =========================
# Case Study Information
# =========================

st.write("## 🔐 Case Study: RESURGE & CVE-2025-0282")

with st.expander("📌 View Vulnerability & Attack Flow"):

    st.write("### Vulnerability Information")

    st.write("**CVE:** CVE-2025-0282")
    st.write("**Affected Product:** Ivanti Connect Secure")
    st.write("**Vulnerability Type:** Stack-Based Buffer Overflow")
    st.write("**Initial Access:** Unauthenticated Exploitation")

    st.write("### 🔄 Attack Flow")

    st.write(
        "Attacker → CVE-2025-0282 → "
        "Ivanti Connect Secure → Initial Access → "
        "RESURGE Malware → Suspicious Behaviour → "
        "VulnGuard Detection → Risk Alert"
    )

    st.write("### 🛡️ VulnGuard Role")

    st.write(
        "VulnGuard analyzes security logs and detects "
        "RESURGE-related indicators and suspicious "
        "malware behaviours. It assigns a risk score "
        "and provides security recommendations."
    )

    st.info(
        "ℹ️ VulnGuard is a defensive log-analysis tool. "
        "It does not execute or reproduce RESURGE malware."
    )

# =========================
# Detection History
# =========================

if "history" not in st.session_state:
    st.session_state.history = []

# =========================
# Upload Log File
# =========================

uploaded_file = st.file_uploader(
    "📁 Upload Security Log",
    type=["log", "txt"]
)

if uploaded_file is not None:

    log_text = uploaded_file.read().decode(
        "utf-8",
        errors="ignore"
    )

    st.success("✅ Log file uploaded successfully!")

    # =========================
    # Log Preview
    # =========================

    st.write("### 📄 Log Preview")

    st.text_area(
        "Security Log",
        log_text,
        height=220
    )

    # =========================
    # Scan Button
    # =========================

    if st.button("🔍 Scan Log"):

        findings = []
        log = log_text.lower()

        # =========================
        # IP Detection
        # =========================

        ip_addresses = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            log_text
        )

        unique_ips = sorted(set(ip_addresses))

        # =========================
        # Attack Detection
        # =========================

        # Path Traversal
        if "../" in log or "..\\" in log:

            findings.append({
                "type": "Path Traversal",
                "risk": "HIGH",
                "score": 40,
                "evidence": "../ pattern detected",
                "why": (
                    "The log contains a path traversal pattern "
                    "that may indicate an attempt to access "
                    "files outside the intended directory."
                )
            })

        # Failed Login
        if "failed login" in log:

            findings.append({
                "type": "Multiple Failed Login Activity",
                "risk": "MEDIUM",
                "score": 20,
                "evidence": "Failed login detected",
                "why": (
                    "Repeated failed login activity may indicate "
                    "a possible unauthorized access attempt."
                )
            })

        # Suspicious Activity
        if "suspicious" in log:

            findings.append({
                "type": "Suspicious Activity",
                "risk": "MEDIUM",
                "score": 20,
                "evidence": "Suspicious activity detected",
                "why": (
                    "The log contains an event marked as "
                    "suspicious and requires further investigation."
                )
            })

        # SQL Injection
        if "union select" in log or "sql injection" in log:

            findings.append({
                "type": "Possible SQL Injection",
                "risk": "HIGH",
                "score": 40,
                "evidence": "SQL injection indicator detected",
                "why": (
                    "SQL injection-related patterns were found "
                    "in the security log."
                )
            })

        # Command Injection
        if "command injection" in log:

            findings.append({
                "type": "Possible Command Injection",
                "risk": "HIGH",
                "score": 40,
                "evidence": "Command injection indicator detected",
                "why": (
                    "The log contains a command injection "
                    "indicator that may represent an attempt "
                    "to execute unintended commands."
                )
            })

        # Malware
        if "malware" in log or "trojan" in log:

            findings.append({
                "type": "Possible Malware Activity",
                "risk": "HIGH",
                "score": 40,
                "evidence": "Malware-related indicator detected",
                "why": (
                    "The log contains malware-related keywords "
                    "that require security investigation."
                )
            })

        # =========================
        # Malware Behaviour Detection
        # =========================

        # Web Shell
        if "web shell" in log or "webshell" in log:

            findings.append({
                "type": "Possible Web Shell Behaviour",
                "risk": "HIGH",
                "score": 40,
                "evidence": "Web shell related activity detected",
                "why": (
                    "Web shell indicators may suggest suspicious "
                    "remote command execution activity."
                )
            })

        # SSH Tunneling
        if "ssh tunnel" in log or "ssh connection" in log:

            findings.append({
                "type": "Possible SSH Tunneling",
                "risk": "HIGH",
                "score": 40,
                "evidence": "SSH tunneling related activity detected",
                "why": (
                    "SSH tunneling-related activity may indicate "
                    "an attempt to create a hidden or unusual "
                    "communication channel."
                )
            })

        # File Modification
        if "modify file" in log or "file modification" in log:

            findings.append({
                "type": "Suspicious File Modification",
                "risk": "MEDIUM",
                "score": 20,
                "evidence": "Suspicious file modification activity detected",
                "why": (
                    "Unexpected file modification activity may "
                    "indicate unauthorized changes to system files."
                )
            })

        # =========================
        # RESURGE Detection
        # =========================

        # RESURGE Indicator
        if "resurge" in log:

            findings.append({
                "type": "Possible RESURGE Malware Indicator",
                "risk": "HIGH",
                "score": 40,
                "evidence": "RESURGE-related indicator found",
                "why": (
                    "The log contains a RESURGE-related indicator "
                    "associated with the malware case study."
                )
            })

        # Boot Disk Manipulation
        if "boot disk" in log:

            findings.append({
                "type": "Possible Boot Disk Manipulation",
                "risk": "HIGH",
                "score": 40,
                "evidence": "Boot disk related activity detected",
                "why": (
                    "Unexpected boot disk activity may indicate "
                    "suspicious modification of system components."
                )
            })

        # Integrity Check Manipulation
        if "integrity check" in log or "integrity checker" in log:

            findings.append({
                "type": "Possible Integrity Check Manipulation",
                "risk": "HIGH",
                "score": 40,
                "evidence": "Integrity check related activity detected",
                "why": (
                    "Attempts to interfere with integrity checking "
                    "may help attackers hide unauthorized changes."
                )
            })

        # =========================
        # Risk Score
        # =========================

        risk_score = sum(
            item["score"] for item in findings
        )

        if risk_score > 100:
            risk_score = 100

        if risk_score >= 70:
            overall_risk = "HIGH"
        elif risk_score >= 30:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        # =========================
        # Security Dashboard
        # =========================

        st.write("## 📊 Security Dashboard")

        col1, col2, col3, col4 = st.columns(4)

        high_risk = sum(
            1
            for item in findings
            if item["risk"] == "HIGH"
        )

        with col1:
            st.metric(
                "Total Detections",
                len(findings)
            )

        with col2:
            st.metric(
                "High Risk",
                high_risk
            )

        with col3:
            st.metric(
                "IP Addresses",
                len(unique_ips)
            )

        with col4:
            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        # =========================
        # Detection Results
        # =========================

        if findings:

            st.error(
                "🚨 SUSPICIOUS ACTIVITY DETECTED"
            )

            st.write(
                f"## ⚠️ Overall Risk: {overall_risk}"
            )

            st.write(
                f"### 🎯 Risk Score: {risk_score}/100"
            )

            st.progress(
                risk_score / 100
            )

            st.write(
                "### 🔎 Detection Results"
            )

            report_lines = []

            report_lines.append(
                "VULNGUARD SECURITY REPORT"
            )

            report_lines.append(
                "=" * 30
            )

            report_lines.append(
                "Scan Time: "
                + datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            report_lines.append(
                "Overall Risk: "
                + overall_risk
            )

            report_lines.append(
                "Risk Score: "
                + str(risk_score)
                + "/100"
            )

            report_lines.append("")

            # =========================
            # Display Findings
            # =========================

            for item in findings:

                st.write(
                    "**Attack / Activity:**",
                    item["type"]
                )

                st.write(
                    "**Risk:**",
                    item["risk"]
                )

                st.write(
                    "**Risk Score:**",
                    item["score"]
                )

                st.write(
                    "**Evidence:**",
                    item["evidence"]
                )

                st.info(
                    "💡 Why detected? "
                    + item["why"]
                )

                st.divider()

                report_lines.append(
                    "Attack / Activity: "
                    + item["type"]
                )

                report_lines.append(
                    "Risk: "
                    + item["risk"]
                )

                report_lines.append(
                    "Risk Score: "
                    + str(item["score"])
                )

                report_lines.append(
                    "Evidence: "
                    + item["evidence"]
                )

                report_lines.append(
                    "Why detected: "
                    + item["why"]
                )

                report_lines.append("")

            # =========================
            # RESURGE Case Study Connection
            # =========================

            resurge_detected = any(
                "RESURGE" in item["type"]
                for item in findings
            )

            if resurge_detected:

                st.write(
                    "### 🔗 RESURGE Case Study Connection"
                )

                st.info(
                    "This detection is related to the RESURGE "
                    "malware case study associated with the "
                    "exploitation of CVE-2025-0282 in "
                    "Ivanti Connect Secure."
                )

                st.write(
                    "**Vulnerability:** CVE-2025-0282"
                )

                st.write(
                    "**Vulnerability Type:** "
                    "Stack-Based Buffer Overflow"
                )

                st.write(
                    "**Initial Access:** "
                    "Unauthenticated exploitation"
                )

                st.write(
                    "**Detected Behaviour:** "
                    "RESURGE-related activity"
                )

                st.warning(
                    "⚠️ The detected indicators require "
                    "further investigation and security monitoring."
                )

                report_lines.append("")
                report_lines.append(
                    "RESURGE CASE STUDY CONNECTION"
                )
                report_lines.append(
                    "Vulnerability: CVE-2025-0282"
                )
                report_lines.append(
                    "Vulnerability Type: "
                    "Stack-Based Buffer Overflow"
                )
                report_lines.append(
                    "Initial Access: "
                    "Unauthenticated exploitation"
                )
                report_lines.append(
                    "Detected Behaviour: "
                    "RESURGE-related activity"
                )

            # =========================
            # IOC Detection
            # =========================

            st.write(
                "### 🚩 IOC Detection"
            )

            if unique_ips:

                st.write(
                    "IP addresses found in the uploaded log:"
                )

                for ip in unique_ips:
                    st.code(ip)

                report_lines.append(
                    "Detected IP Addresses:"
                )

                report_lines.extend(
                    unique_ips
                )

            else:

                st.write(
                    "No IP-based IOC found."
                )

            # =========================
            # Recommended Action
            # =========================

            st.write(
                "### 🛡️ Recommended Action"
            )

            recommendation = (
                "Investigate the affected system, "
                "review security logs, check suspicious "
                "IP activity and apply appropriate "
                "security patches."
            )

            st.info(
                recommendation
            )

            report_lines.append("")

            report_lines.append(
                "Recommended Action:"
            )

            report_lines.append(
                recommendation
            )

            # =========================
            # Detection History
            # =========================

            scan_record = {
                "time":
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                "file":
                    uploaded_file.name,
                "risk":
                    overall_risk,
                "score":
                    risk_score,
                "detections":
                    len(findings)
            }

            st.session_state.history.append(
                scan_record
            )

            # =========================
            # Download Security Report
            # =========================

            report_text = "\n".join(
                report_lines
            )

            st.download_button(
                "📄 Download Security Report",
                report_text,
                file_name=
                    "VulnGuard_Security_Report.txt",
                mime="text/plain"
            )

        else:

            st.success(
                "✅ No known suspicious activity detected"
            )

            st.write(
                "## Risk Level: LOW"
            )

            st.write(
                "### 🎯 Risk Score: 0/100"
            )

            st.progress(0)

        # =========================
        # Detection History
        # =========================

        st.write(
            "## 📋 Detection History"
        )

        if st.session_state.history:

            for record in reversed(
                st.session_state.history
            ):

                st.write(
                    f"🕒 {record['time']} | "
                    f"📁 {record['file']} | "
                    f"⚠️ Risk: {record['risk']} | "
                    f"🎯 Score: {record['score']}/100 | "
                    f"🔎 Detections: "
                    f"{record['detections']}"
                )

        else:

            st.write(
                "No previous scans."
            )