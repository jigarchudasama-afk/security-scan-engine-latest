#!/bin/bash
set -eo pipefail

# --- Configuration ---
HOST_ROOT="/host"
SCC_DIR="${HOST_ROOT}/opt/mount/scan_container"
SCANNER_CONTENT_DIR="/scanner_files/scc-5.10_rhel8_x86_64"
BENCHMARK_FILE="U_RHEL_8_V2R1_STIG_SCAP_1-3_Benchmark.zip"
BENCHMARK_SRC_PATH="/scanner_files/${BENCHMARK_FILE}"
BENCHMARK_DEST_PATH="${SCC_DIR}/${BENCHMARK_FILE}"
RESULTS_DIR="${SCC_DIR}/Resources/Results"
LOG_FILE="${SCC_DIR}/stig_scan.log"

# --- Logging Function ---
print2log() {
  local message="$1"
  local timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# --- Functional Logic ---

##
# Installs the SCC scanner from the container to the host if not present.
##
install_scanner_if_needed() {
    if [ -f "${SCC_DIR}/cscc" ]; then
        print2log "INFO: Scanner already installed at ${SCC_DIR}, skipping extraction..."
    else
        print2log "INFO: Copying scanner from ${SCANNER_CONTENT_DIR}..."
        cd "${SCANNER_CONTENT_DIR}"
        print2log "INFO: Copying scanner files to ${SCC_DIR}..."
        cp -rT scc_5.10/ "${SCC_DIR}/"
    fi
}

##
# Copies the STIG benchmark zip file to the host if not present.
##
copy_benchmark_if_needed() {
    if [ ! -f "${BENCHMARK_DEST_PATH}" ]; then
        print2log "INFO: Copying STIG benchmark..."
        cp "${BENCHMARK_SRC_PATH}" "${SCC_DIR}/"
    else
        print2log "INFO: STIG benchmark already present, skipping copy..."
    fi
}

##
# Installs the STIG benchmark profile using the cscc scanner.
# @return 0 on success, 1 on failure
##
install_benchmark_profile() {
    print2log "INFO: Installing STIG benchmark profile..."
    if chroot "${HOST_ROOT}" /opt/mount/scan_container/cscc -is "/opt/mount/scan_container/${BENCHMARK_FILE}"; then
        print2log "SUCCESS: STIG benchmark profile installed."
        return 0
    else
        print2log "ERROR: Failed to install STIG benchmark profile."
        return 1
    fi
}

##
# Runs the main STIG compliance scan.
# @return 0 on success, 1 on failure
##
run_stig_scan() {
    print2log "INFO: Starting STIG scan on host. This may take a while..."
    mkdir -p "${RESULTS_DIR}"

    # Redirect stdout/stderr to a log file
    chroot "${HOST_ROOT}" /opt/mount/scan_container/cscc -u /opt/mount/scan_container/Resources/Results/ > "${SCC_DIR}/output.txt" 2>&1
    local scan_exit_code=$?

    if [ $scan_exit_code -ne 0 ]; then
        print2log "ERROR: STIG scan command failed with exit code $scan_exit_code. Check output.txt for details."
        return 1
    else
        print2log "SUCCESS: STIG scan command completed."
        return 0
    fi
}

# --- Main Execution ---

##
# Main orchestrator function for the STIG scan
##
main() {
    print2log "--- STIG scan process started from container ---"

    # 1. Prepare SCC installation directory
    # print2log "INFO: Preparing SCC directory at ${SCC_DIR}..."
    # mkdir -p "${SCC_DIR}"

    # 2. Install scanner
    install_scanner_if_needed

    # 3. Copy benchmark
    copy_benchmark_if_needed

    # 4. Install benchmark profile
    if ! install_benchmark_profile; then
        exit 1
    fi

    # 5. Run the scan
    if ! run_stig_scan; then
        exit 1
    fi

    print2log "--- STIG scan operation completed successfully ---"
    print2log "Raw results and logs are located in /opt/scc on the host."
    exit 0
}

# Run the main function
main