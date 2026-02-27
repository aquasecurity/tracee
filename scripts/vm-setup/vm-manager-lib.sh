#!/bin/bash
# VM Manager library: config, prompts, path wizard.
# Source from vm-manager.sh. Expects CONFIG_DIR, CONFIG_FILE, SCRIPT_DIR to be set.

set -euo pipefail

# Load path config if present
load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        set -a
        # shellcheck source=/dev/null disable=SC1090
        . "${CONFIG_FILE}"
        set +a
    fi
}

exit_gum_required() {
    cat << EOF
Interactive mode requires 'gum' to be installed.

Install instructions:
  https://github.com/charmbracelet/gum#installation

Examples:
  Ubuntu/Debian:  sudo apt install gum
  Fedora:         sudo dnf install gum
  macOS:          brew install gum

You can use the manager without the TUI by passing commands and flags, for example:
  $0 download --distro ubuntu --version 24.04 --arch x86_64
  $0 run-dev <image-name>
  $0 --help
EOF
    exit 1
}

print_error() {
    gum style --foreground 196 --bold "$*" >&2
}

print_info() {
    gum style --foreground 6 "$*" >&2
}

# Print a step/section header so output is clearly grouped (e.g. "1. Download", "2. Verify").
print_step_header() {
    gum format "## $*"
}

# Download URL to dest_tmp with a progress bar (polls file size). Returns exit code of curl/wget.
download_with_progress() {
    local url="${1:?}"
    local dest_tmp="${2:?}"
    local total_bytes
    total_bytes=$(curl -sI -L "${url}" 2>/dev/null | grep -i '^content-length:' | awk '{print $2}' | tr -d '\r')
    [[ -z "${total_bytes}" || ! "${total_bytes}" =~ ^[0-9]+$ ]] && total_bytes=0
    if command -v curl &>/dev/null; then
        curl -fsSL -o "${dest_tmp}" "${url}" &
    else
        wget -q -O "${dest_tmp}" "${url}" &
    fi
    local pid=$!
    local current=0 pct=0 total_mb=0 cur_mb=0
    [[ "${total_bytes}" -gt 0 ]] && total_mb=$((total_bytes / 1024 / 1024))
    while kill -0 "${pid}" 2>/dev/null; do
        current=$(stat -c %s "${dest_tmp}" 2>/dev/null || stat -f %z "${dest_tmp}" 2>/dev/null || echo 0)
        cur_mb=$((current / 1024 / 1024))
        if [[ "${total_bytes}" -gt 0 ]]; then
            pct=$((current * 100 / total_bytes))
            [[ ${pct} -gt 100 ]] && pct=100
            local filled=$((pct * 24 / 100))
            local empty=$((24 - filled))
            local bar
            bar=$(printf "%${filled}s" "" | tr ' ' '=')$(printf "%${empty}s" "" | tr ' ' ' ')
            printf "\r  [%s] %3d%%  %s MB / %s MB   " "${bar}" "${pct}" "${cur_mb}" "${total_mb}"
        else
            printf "\r  Downloading... %s MB   " "${cur_mb}"
        fi
        sleep 0.25
    done
    if [[ "${total_bytes}" -gt 0 ]]; then
        printf "\r  [========================] 100%%  %s MB / %s MB   \n" "${total_mb}" "${total_mb}"
    else
        printf "\r  Done. %s MB   \n" "${cur_mb}"
    fi
    wait "${pid}"
}

# Prompt for a path until non-empty. On Ctrl+C exits (trap must be set by caller).
prompt_path() {
    local header="$1"
    local default="$2"
    local val
    while true; do
        val=$(gum input --header "${header}" --placeholder "Path" --value "${default}")
        local status=$?
        if (( status != 0 )); then
            exit 130
        fi
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"
        if [[ -n "${val}" ]]; then
            if [[ -d "${val}" ]]; then
                print_info "Directory exists, using it."
            fi
            echo "${val}"
            return
        fi
        print_error "Path cannot be empty. Please enter a valid directory path."
    done
}

run_path_wizard() {
    local base_dir output_dir s3_bucket
    trap 'exit 130' INT
    base_dir=$(prompt_path "Base images directory – where upstream cloud images are downloaded and kept (e.g. ${HOME}/vms/base-images)" "${HOME}/vms/base-images")
    gum format "Base images directory: **${base_dir}**"
    output_dir=$(prompt_path "Output images directory – where customized/created images are written (e.g. ${HOME}/vms)" "${HOME}/vms")
    gum format "Output images directory: **${output_dir}**"
    s3_bucket=$(gum input --header "S3 bucket for AMI upload (optional – leave empty if not pushing to AWS)" --placeholder "e.g. my-tracee-ami-bucket" --value "${S3_BUCKET:-}")
    s3_bucket="${s3_bucket#"${s3_bucket%%[![:space:]]*}"}"
    s3_bucket="${s3_bucket%"${s3_bucket##*[![:space:]]}"}"
    if [[ -n "${s3_bucket}" ]]; then
        gum format "S3 bucket: **${s3_bucket}**"
    fi
    mkdir -p "${CONFIG_DIR}"
    cat > "${CONFIG_FILE}" << EOF
# Tracee VM Manager path configuration (generated)
BASE_IMAGES_DIR="${base_dir}"
OUTPUT_IMAGES_DIR="${output_dir}"
S3_BUCKET="${s3_bucket:-}"
EOF
    BASE_IMAGES_DIR="${base_dir}"
    OUTPUT_IMAGES_DIR="${output_dir}"
    S3_BUCKET="${s3_bucket:-}"
    export BASE_IMAGES_DIR OUTPUT_IMAGES_DIR S3_BUCKET
    gum format "Paths saved to ${CONFIG_FILE}"
}
