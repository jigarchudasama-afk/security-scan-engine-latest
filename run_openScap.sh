#!/bin/bash
set -eo pipefail

HOST_ROOT="/host"
SCC_DIR="${HOST_ROOT}/opt/mount/scan_container"
OUTPUT_DIR="${SCC_DIR}/openscap_results"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
LOG_FILE="${OUTPUT_DIR}/${TIMESTAMP}_scan.log"
CONFIG_FILE="${SCC_DIR}/scan_setup.config"

OVAL_PATCHED_URL="https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2"
OVAL_PATCHED_FILE="rhel-8.oval.xml"
OVAL_PATCHED_REPORT="${OUTPUT_DIR}/${TIMESTAMP}_patched_vulnerabilities.html"

OVAL_UNPATCHED_URL="https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8-including-unpatched.oval.xml.bz2"
OVAL_UNPATCHED_FILE="rhel-8-including-unpatched.xml"
OVAL_UNPATCHED_REPORT="${OUTPUT_DIR}/${TIMESTAMP}_unpatched_vulnerabilities.html"

# --- NEW LOGIC: Respect existing variable, default to CVE only if missing ---
SCANS_TO_RUN="${SCANS_TO_RUN:-CVE}"

print2log() {
  local message="$1"
  local timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        # If config file is empty, SCANS_TO_RUN retains its previous value (from -e)
        print2log "INFO: Loaded config. SCANS_TO_RUN is set to '$SCANS_TO_RUN'."
    else
        print2log "WARNING: Config file $CONFIG_FILE not found. Using env var or default."
    fi
}

download_oval_file() {
    local url="$1"
    local dest_file="$2"
    local scan_type="$3"
    print2log "INFO: Downloading OVAL file for ${scan_type} vulnerabilities..."
    if wget -q -O - "${url}" | bzip2 --decompress > "${dest_file}"; then
        print2log "SUCCESS: OVAL file for ${scan_type} scan downloaded."
        return 0
    else
        print2log "FAILURE: Failed to download OVAL file for ${scan_type} scan."
        return 1
    fi
}

run_oscap_scan() {
    local report_file="$1"
    local oval_file="$2"
    local scan_type="$3"
    print2log "INFO: Running OpenSCAP evaluation on the host VM for ${scan_type} scan..."
    if oscap oval eval --report "${report_file}" "${oval_file}" &> /dev/null; then
        print2log "SUCCESS: ${scan_type} vulnerability scan complete."
        return 0
    else
        print2log "FAILURE: 'oscap' command failed for the ${scan_type} scan."
        return 1
    fi
}

cleanup_files() {
    print2log "INFO: Cleaning up temporary OVAL files..."
    if rm -f "$@"; then
        print2log "SUCCESS: Cleanup complete."
        return 0
    else
        print2log "FAILURE: Failed to clean up temporary files."
        return 1
    fi
}

main() {
    mkdir -p "${OUTPUT_DIR}"
    print2log "--- OpenSCAP Scan Started: $(date) ---"
    load_config

    # Always run patched (CVE)
    download_oval_file "${OVAL_PATCHED_URL}" "${OVAL_PATCHED_FILE}" "patched" || exit 1
    run_oscap_scan "${OVAL_PATCHED_REPORT}" "${OVAL_PATCHED_FILE}" "patched" || exit 1

    if [ "$SCANS_TO_RUN" == "ALL" ]; then
        print2log "INFO: 'ALL' scans selected, running unpatched vulnerability scan..."
        download_oval_file "${OVAL_UNPATCHED_URL}" "${OVAL_UNPATCHED_FILE}" "unpatched" || exit 1
        run_oscap_scan "${OVAL_UNPATCHED_REPORT}" "${OVAL_UNPATCHED_FILE}" "unpatched" || exit 1
        cleanup_files "${OVAL_PATCHED_FILE}" "${OVAL_UNPATCHED_FILE}" || exit 1
    else
        print2log "INFO: Skipping unpatched scan as per configuration."
        cleanup_files "${OVAL_PATCHED_FILE}" || exit 1
    fi

    print2log "All configured OpenSCAP scans finished successfully."
    print2log "Results are located in ${OUTPUT_DIR} on the host."
    print2log "--- OpenSCAP Scan Finished: $(date) ---"
    exit 0
}

main