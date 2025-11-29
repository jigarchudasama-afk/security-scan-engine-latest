#!/bin/bash
set -eo pipefail

# --- Configuration ---
HOST_ROOT="/host"
HOST_SCAN_DIR="${HOST_ROOT}/opt/mount/scan_container"
LOG_FILE="${HOST_SCAN_DIR}/mail.log"
SMTP_SERVER="smtp://smtp.gmail.com:587"

# --- Globals ---
SESSIONS_DIR="${HOST_SCAN_DIR}/Resources/Results/Sessions"
OPENSCAP_DIR="${HOST_SCAN_DIR}/openscap_results"

# These will be set by find_report_files
STIG_REPORT_FILE=""
PATCHED_REPORT_FILE=""
UNPATCHED_REPORT_FILE=""

# This will be populated by find_all_attachments
declare -a attachments=()

# --- Logging Function ---
print2log() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# --- Functional Logic ---

load_credentials() {
    print2log "INFO: Loading credentials and configuration..."
    export RECIPIENT_EMAIL="${RECIPIENT_EMAIL:?Error: RECIPIENT_EMAIL not set}"
    export SENDER_EMAIL="${SENDER_EMAIL:?Error: SENDER_EMAIL not set}"
    export SMTP_USER="${SMTP_USER:?Error: SMTP_USER not set}"
    export SMTP_PASS="${SMTP_PASS:?Error: SMTP_PASS not set}"
    export SCANS_TO_RUN="${SCANS_TO_RUN:-ALL}"
    print2log "INFO: Credentials loaded. Email scope set to: $SCANS_TO_RUN"
}

find_report_files() {
    print2log "INFO: Locating specific reports for data scraping..."
    
    # STIG Search
    if [[ "$SCANS_TO_RUN" == "STIG" || "$SCANS_TO_RUN" == "ALL" ]]; then
        local latest_stig_session_dir
        latest_stig_session_dir=$(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1)
        STIG_REPORT_FILE=$(find "${latest_stig_session_dir}/Results/SCAP" -name "*All-Settings_RHEL_8_STIG*.html" 2>/dev/null | head -n 1)
    else
        print2log "INFO: Skipping STIG report search (Config: $SCANS_TO_RUN)"
    fi

    # OpenSCAP Search
    if [[ "$SCANS_TO_RUN" == "CVE" || "$SCANS_TO_RUN" == "ALL" ]]; then
        PATCHED_REPORT_FILE=$(find "$OPENSCAP_DIR" -maxdepth 1 -name "*_patched_vulnerabilities.html" 2>/dev/null | sort -r | head -n 1)
        if [[ "$SCANS_TO_RUN" == "ALL" ]]; then
            UNPATCHED_REPORT_FILE=$(find "$OPENSCAP_DIR" -maxdepth 1 -name "*_unpatched_vulnerabilities.html" 2>/dev/null | sort -r | head -n 1)
        fi
    else
        print2log "INFO: Skipping OpenSCAP report search (Config: $SCANS_TO_RUN)"
    fi
}

scrape_stig_summary() {
    if [ -f "$STIG_REPORT_FILE" ]; then
        print2log "INFO: Scraping STIG data from $(basename "$STIG_REPORT_FILE")"
        local stig_score stig_status pass_line stig_pass stig_na fail_line stig_fail stig_nc total_line stig_total

        stig_score=$(grep 'Adjusted Score:' "$STIG_REPORT_FILE" | sed -n 's/.*<td class="label">Adjusted Score:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        stig_status=$(grep 'Compliance Status:' "$STIG_REPORT_FILE" | sed -n 's/.*<td class="labelBold">Compliance Status:<\/td><td class="valueBold">\([^<]*\)<\/td>.*/\1/p')
        pass_line=$(grep 'Pass:' "$STIG_REPORT_FILE" | grep '<td class="label">Pass:</td>')
        stig_pass=$(echo "$pass_line" | sed -n 's/.*<td class="label">Pass:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        stig_na=$(echo "$pass_line" | sed -n 's/.*<td class="label">Not Applicable:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        fail_line=$(grep 'Fail:' "$STIG_REPORT_FILE" | grep '<td class="label">Fail:</td>')
        stig_fail=$(echo "$fail_line" | sed -n 's/.*<td class="label">Fail:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        stig_nc=$(echo "$fail_line" | sed -n 's/.*<td class="label">Not Checked:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        total_line=$(grep 'Total:' "$STIG_REPORT_FILE" | grep '<td class="label">Total:</td>')
        stig_total=$(echo "$total_line" | sed -n 's/.*<td class="label">Total:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
        
        export STIG_SCORE=$(echo "$stig_score" | xargs)
        export STIG_STATUS=$(echo "$stig_status" | xargs)
        export STIG_PASS=$(echo "$stig_pass" | xargs)
        export STIG_FAIL=$(echo "$stig_fail" | xargs)
        export STIG_TOTAL=$(echo "$stig_total" | xargs)
        export STIG_NOT_APPLICABLE=$(echo "$stig_na" | xargs)
        export STIG_NOT_CHECKED=$(echo "$stig_nc" | xargs)
    else
        export STIG_SCORE="N/A" STIG_STATUS="N/A" STIG_PASS="N/A" STIG_FAIL="N/A" STIG_TOTAL="N/A" STIG_NOT_APPLICABLE="N/A" STIG_NOT_CHECKED="N/A"
    fi
}

scrape_patched_summary() {
    if [ -f "$PATCHED_REPORT_FILE" ]; then
        print2log "INFO: Scraping Patched OpenSCAP data from $(basename "$PATCHED_REPORT_FILE")"
        export PATCHED_FAIL=$(grep 'resultbadB' "$PATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
        export PATCHED_PASS=$(grep 'resultgoodB' "$PATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
        export PATCHED_TOTAL=$(sed -n 's/.*<td class="SmallText Center">\([0-9]\{1,\}\) Total.*/\1/p' "$PATCHED_REPORT_FILE" | head -n 1)
    else
        export PATCHED_FAIL="N/A" PATCHED_PASS="N/A" PATCHED_TOTAL="N/A"
    fi
}

scrape_unpatched_summary() {
    if [ -f "$UNPATCHED_REPORT_FILE" ]; then
        print2log "INFO: Scraping Unpatched OpenSCAP data from $(basename "$UNPATCHED_REPORT_FILE")"
        export UNPATCHED_FAIL=$(grep 'resultbadB' "$UNPATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
        export UNPATCHED_PASS=$(grep 'resultgoodB' "$UNPATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
        export UNPATCHED_TOTAL=$(sed -n 's/.*<td class="SmallText Center">\([0-9]\{1,\}\) Total.*/\1/p' "$UNPATCHED_REPORT_FILE" | head -n 1)
    else
        export UNPATCHED_FAIL="N/A" UNPATCHED_PASS="N/A" UNPATCHED_TOTAL="N/A"
    fi
}

prepare_email_variables() {
    print2log "INFO: Preparing variables for HTML email body..."
    # Try to get hostname from file, fallback to command
    if [ -f /host/etc/hostname ]; then
        export HOSTNAME=$(cat /host/etc/hostname)
    else
        export HOSTNAME=$(hostname)
    fi
    
    export SCAN_DATE=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Dynamic Subject Line
    if [ "$SCANS_TO_RUN" == "STIG" ]; then
        export EMAIL_SUBJECT="STIG Compliance Results for $HOSTNAME"
    elif [ "$SCANS_TO_RUN" == "CVE" ]; then
        export EMAIL_SUBJECT="Vulnerability Scan Results for $HOSTNAME"
    else
        export EMAIL_SUBJECT="Security Scan Results for $HOSTNAME"
    fi

    local status_color
    case "$STIG_STATUS" in
        *"GREEN"*|*"green"*) status_color="#28a745";;
        *"BLUE"*|*"blue"*) status_color="#007bff";;
        *"YELLOW"*|*"yellow"*) status_color="#ffc107";;
        *"RED"*|*"red"*) status_color="#dc3545";;
        *) status_color="#6c757d";;
    esac
    export STATUS_COLOR="$status_color"
}

find_all_attachments() {
    print2log "INFO: Searching for all report files to attach..."
    
    # OpenSCAP Attachments
    if [[ "$SCANS_TO_RUN" == "CVE" || "$SCANS_TO_RUN" == "ALL" ]]; then
        if [ -d "$OPENSCAP_DIR" ] && [ -n "$(ls -A "$OPENSCAP_DIR")" ]; then
            while IFS= read -r file; do
                if [ -f "$file" ]; then
                    # If CVE mode, skip unpatched files if they exist
                    if [[ "$SCANS_TO_RUN" == "CVE" && "$file" == *"unpatched"* ]]; then
                        continue
                    fi
                    attachments+=("$file")
                    print2log "INFO: Attaching OpenSCAP report: $(basename "$file")"
                fi
            done < <(find "$OPENSCAP_DIR" -maxdepth 1 -name "*.html")
        fi
    fi

    # STIG Attachments
    if [[ "$SCANS_TO_RUN" == "STIG" || "$SCANS_TO_RUN" == "ALL" ]]; then
        if [ -d "$SESSIONS_DIR" ] && [ -n "$(ls -A "$SESSIONS_DIR")" ]; then
            local latest_stig_dir
            latest_stig_dir="${SESSIONS_DIR}/$(ls -1t "$SESSIONS_DIR" | head -n 1)/Results/SCAP"
            if [ -d "$latest_stig_dir" ]; then
                find "$latest_stig_dir" -type f -name "*1.13.10*" -delete
                while IFS= read -r file; do
                    if [ -f "$file" ]; then
                        attachments+=("$file")
                        print2log "INFO: Attaching STIG report: $(basename "$file")"
                    fi
                done < <(find "$latest_stig_dir" -name "*.html")
            fi
        fi
    fi
}

send_email() {
    if [ "${#attachments[@]}" -eq 0 ]; then
        print2log "WARNING: No HTML reports found to attach. Nothing to send."
        return 0
    fi

    export ATTACHMENT_FILES="${attachments[*]}"
    export SMTP_HOST=$(echo "$SMTP_SERVER" | sed -e 's,smtp://,,g' -e 's,:.*,,g')
    export SMTP_PORT=$(echo "$SMTP_SERVER" | sed -e 's,.*:,,g')
    [ -z "$SMTP_PORT" ] && export SMTP_PORT=587

    print2log "INFO: Connecting to $SMTP_HOST:$SMTP_PORT..."
    print2log "INFO: Sending email with dynamic HTML body and ${#attachments[@]} attachments via Python..."

    python3 -c '
import os
import smtplib
import mimetypes
from email.message import EmailMessage
from email.utils import formatdate

# --- 1. Load Environment Variables ---
sender = os.environ.get("SENDER_EMAIL")
recipient = os.environ.get("RECIPIENT_EMAIL")
subject = os.environ.get("EMAIL_SUBJECT")
smtp_host = os.environ.get("SMTP_HOST")
smtp_port = int(os.environ.get("SMTP_PORT", 587))
smtp_user = os.environ.get("SMTP_USER")
smtp_pass = os.environ.get("SMTP_PASS")
scan_mode = os.environ.get("SCANS_TO_RUN", "ALL")

hostname = os.environ.get("HOSTNAME")
scan_date = os.environ.get("SCAN_DATE")
status_color = os.environ.get("STATUS_COLOR")

# Data Variables
stig_score = os.environ.get("STIG_SCORE")
stig_status = os.environ.get("STIG_STATUS")
stig_total = os.environ.get("STIG_TOTAL")
stig_pass = os.environ.get("STIG_PASS")
stig_fail = os.environ.get("STIG_FAIL")
stig_na = os.environ.get("STIG_NOT_APPLICABLE")
stig_nc = os.environ.get("STIG_NOT_CHECKED")

patched_pass = os.environ.get("PATCHED_PASS")
patched_fail = os.environ.get("PATCHED_FAIL")
patched_total = os.environ.get("PATCHED_TOTAL")

unpatched_pass = os.environ.get("UNPATCHED_PASS")
unpatched_fail = os.environ.get("UNPATCHED_FAIL")
unpatched_total = os.environ.get("UNPATCHED_TOTAL")

# --- 2. Define HTML Fragments ---

# Dynamic Description Text
description_text = "security scans"
if scan_mode == "STIG":
    description_text = "STIG compliance scan"
elif scan_mode == "CVE":
    description_text = "patched vulnerability scan"
elif scan_mode == "ALL":
    description_text = "comprehensive security scans (STIG + Vulnerabilities)"

# Table: Patched Vulnerabilities
patched_table_html = f"""
<h3 style="margin-top: 25px;">Vulnerabilities Scan Report (Patched)</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{patched_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Patched</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{patched_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Vulnerable</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{patched_fail}</td>
</tr>
</table>
"""

# Table: STIG Compliance
stig_table_html = f"""
<h3 style="margin-top: 25px;">STIG Compliance Summary</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Adjusted Score</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_score}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Compliance Status</td>
<td style="border: 1px solid #999; padding: 8px; background-color: {status_color}; color: white;">{stig_status}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total Checks</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Passed</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{stig_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Failed</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{stig_fail}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Not Applicable</td>
<td style="border: 1px solid #999; padding: 8px;">{stig_na}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Not Checked</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_nc}</td>
</tr>
<tr>
<td colspan="2" style="border: 1px solid #999; padding: 10px; font-size: 12px; line-height: 1.4; background-color: #fafafa;">
    <b>Color Key:</b><br>
    <span style="color: #007bff;">&#9632;</span> <b>BLUE:</b> Score equals 100<br>
    <span style="color: #28a745;">&#9632;</span> <b>GREEN:</b> Score is greater than or equal to 90<br>
    <span style="color: #ffc107;">&#9632;</span> <b>YELLOW:</b> Score is greater than or equal to 80<br>
    <span style="color: #dc3545;">&#9632;</span> <b>RED:</b> Score is greater than or equal to 0
</td>
</tr>
</table>
"""

# Table: Unpatched Vulnerabilities
unpatched_table_html = f"""
<h3 style="margin-top: 25px;">Unpatched Vulnerabilities Report</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{unpatched_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Patched</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{unpatched_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Vulnerable</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{unpatched_fail}</td>
</tr>
</table>
"""

# --- 3. Build Final HTML Body ---
html_content = f"""
<html>
<body style="font-family: Arial, sans-serif; margin: 20px;">
<h2>System Security Scan Summary</h2>
<p style="font-size: 14px; color: #333;">Here is a high-level summary of the latest <b>{description_text}</b> for <b>{hostname}</b>.</p>
<p><b>Hostname:</b> {hostname}<br>
<b>Date:</b> {scan_date}</p>
"""

# Conditionally append tables based on scan_mode
# CVE Mode: Show Patched only
if scan_mode == "CVE":
    html_content += patched_table_html

# ALL Mode: Show Patched + Unpatched + STIG
elif scan_mode == "ALL":
    html_content += patched_table_html
    html_content += stig_table_html
    html_content += unpatched_table_html

# STIG Mode: Show STIG only
elif scan_mode == "STIG":
    html_content += stig_table_html

html_content += """
<p style="margin-top: 25px; font-size: 12px; color: #888;">This is an automated message. Full, detailed HTML reports are attached to this email.</p>
</body>
</html>
"""

# --- 4. Send Email ---
msg = EmailMessage()
msg["Subject"] = subject
msg["From"] = sender
msg["To"] = recipient
msg["Date"] = formatdate(localtime=True)
msg.set_content("Please enable HTML to view this report.")
msg.add_alternative(html_content, subtype="html")

attachment_paths = os.environ.get("ATTACHMENT_FILES", "").split()
for path in attachment_paths:
    if not os.path.isfile(path):
        continue
    ctype, encoding = mimetypes.guess_type(path)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)
    with open(path, "rb") as fp:
        msg.add_attachment(fp.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(path))

try:
    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
    print("Python: Email sent successfully.")
except Exception as e:
    print(f"Python: Error sending email: {e}")
    exit(1)
'
    local mail_exit_code=$?
    if [ $mail_exit_code -eq 0 ]; then
        print2log "SUCCESS: Email sent successfully."
    else
        print2log "FAILURE: Python email script failed. Check logs."
        exit 1
    fi
}

# --- Main Execution ---
main() {
    print2log "--- Email notification script started ---"
    load_credentials
    find_all_attachments
    find_report_files
    print2log "INFO: Scraping summary data from reports..."
    scrape_stig_summary
    scrape_patched_summary
    scrape_unpatched_summary
    prepare_email_variables
    send_email
    print2log "--- Email notification script finished ---"
    exit 0
}
main