#!/bin/bash

# --- Configuration ---
HOST_ROOT="/host"
SCC_DIR="${HOST_ROOT}/opt/mount/scan_container"
LOG_FILE="${SCC_DIR}/security_scans.log"
CONFIG_FILE="${SCC_DIR}/scan_setup.config"

# Counters
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_COUNT=0

print2log() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

load_config() {
    # --- NEW LOGIC: Auto-create empty config if missing ---
    if [ ! -f "$CONFIG_FILE" ]; then
        print2log "INFO: Configuration file not found at $CONFIG_FILE."
        print2log "INFO: Creating empty config file to allow execution via environment variables."
        touch "$CONFIG_FILE"
    fi
    
    # Source the file (it might be empty, which is fine)
    source "$CONFIG_FILE"
    
    # Check variables (whether they came from the file or -e flags)
    if [ -z "$SENDER_EMAIL" ] || [ -z "$SMTP_USER" ] || [ -z "$SMTP_PASS" ] || [ -z "$RECIPIENT_EMAIL" ]; then
        echo "ERROR: One or more required email variables are missing. Please set them via scan_setup.config OR -e flags." >&2
        exit 1
    fi
    
    if [ -z "$SCANS_TO_RUN" ]; then
        echo "ERROR: SCANS_TO_RUN is not set. Please set it via scan_setup.config OR -e flags." >&2
        exit 1
    fi
}

cleanup_old_results() {
    print2log "--- Cleaning up old log and result files ---"
    rm -f "${SCC_DIR}/security_scans.log"
    rm -f "${SCC_DIR}/stig_scan.log"
    rm -f "${SCC_DIR}/output.txt"
    rm -f "${SCC_DIR}/mail.log"
    if [ -d "${SCC_DIR}/openscap_results" ]; then
        rm -f "${SCC_DIR}/openscap_results"/*
    fi
    print2log "--- Old files cleaned up ---"
}

run_scan_script() {
    local script_path="$1"
    local script_name
    script_name=$(basename "$script_path")

    if [ -x "$script_path" ]; then
        print2log "Launching $script_name..."
        "$script_path"
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print2log "SUCCESS: $script_name completed successfully."
            return 0
        else
            print2log "ERROR: $script_name failed with exit code $exit_code."
            return 1
        fi
    else
        print2log "ERROR: $script_name not found or not executable at $script_path"
        return 1
    fi
}

run_all_scans() {
    local i script_path script_name count exit_code
    local SCRIPTS_TO_RUN=()

    case "$SCANS_TO_RUN" in
        STIG) SCRIPTS_TO_RUN=("/app/run_STIG.sh") ;;
        CVE)  SCRIPTS_TO_RUN=("/app/run_openScap.sh") ;;
        ALL)  SCRIPTS_TO_RUN=("/app/run_openScap.sh" "/app/run_STIG.sh") ;;
        *)
            print2log "ERROR: Invalid value for SCANS_TO_RUN: '$SCANS_TO_RUN'. Must be STIG, CVE, or ALL."
            FAILURE_COUNT=1
            return
            ;;
    esac

    TOTAL_COUNT=${#SCRIPTS_TO_RUN[@]}
    print2log "Total scripts to process: $TOTAL_COUNT"
    print2log ""
    
    for i in "${!SCRIPTS_TO_RUN[@]}"; do
        script_path="${SCRIPTS_TO_RUN[$i]}"
        script_name=$(basename "$script_path")
        count=$((i + 1))

        print2log "[$count/$TOTAL_COUNT] ===== Executing $script_name ====="
        run_scan_script "$script_path"
        exit_code=$?

        if [ $exit_code -eq 0 ]; then
            ((SUCCESS_COUNT++))
        else
            ((FAILURE_COUNT++))
        fi
        print2log "[$count/$TOTAL_COUNT] ===== $script_name execution completed ====="
        print2log ""
    done
}

trigger_notification() {
    if [ "$TOTAL_COUNT" -gt 0 ] && [ "$SUCCESS_COUNT" -eq "$TOTAL_COUNT" ]; then
        print2log "All scans successful. Triggering email notification script..."
        /app/email.sh
    elif [ "$TOTAL_COUNT" -eq 0 ]; then
        print2log "No scans were configured to run. Skipping email."
    else
        print2log "One or more scans failed. Skipping email notification."
    fi
    print2log ""
}

print_summary() {
    print2log "===== All Scans Finished ====="
    print2log "Total scripts processed: $TOTAL_COUNT"
    print2log "Successful scripts: $SUCCESS_COUNT"
    print2log "Failed scripts: $FAILURE_COUNT"
    print2log "=============================="
    print2log "removing $SCC_DIR"
    rm -rf "$SCC_DIR"
}

main() {
    if [ ! -d "$SCC_DIR" ]; then
        print2log "INFO: scc folder not found at $SCC_DIR."
        print2log "INFO: Creating $SCC_DIR folder"
        mkdir -p "$SCC_DIR"
    fi
    load_config
    cleanup_old_results
    print2log ""
    print2log "===== Security Scan Orchestrator Started ====="
    print2log "Configuration loaded. SCANS_TO_RUN set to: $SCANS_TO_RUN"
    run_all_scans
    trigger_notification
    print_summary
    if [ "$FAILURE_COUNT" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main