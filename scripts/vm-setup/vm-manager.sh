#!/bin/bash
# VM Image Manager – distro-agnostic orchestrator. Interactive TUI or command dispatch.
# Sources: vm-manager-lib.sh (config, prompts), distros/*.sh (download, build per distro).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.tracee-vm-manager"
# CONFIG_FILE used by vm-manager-lib.sh when sourced
# shellcheck disable=SC2034
CONFIG_FILE="${CONFIG_DIR}/config.env"
DISTROS_DIR="${SCRIPT_DIR}/distros"

# shellcheck disable=SC1091
. "${SCRIPT_DIR}/vm-manager-lib.sh"

# Discover distros that provide download: set DISTRO_IDS, DISTRO_NAMES, DISTRO_FILES
discover_download_distros() {
    DISTRO_IDS=()
    DISTRO_NAMES=()
    DISTRO_FILES=()
    local f
    for f in "${DISTROS_DIR}"/*.sh; do
        [[ -f "${f}" ]] || continue
        # shellcheck source=/dev/null
        . "${f}"
        if type distro_download_run &>/dev/null; then
            # shellcheck disable=SC2153
            DISTRO_IDS+=("${DISTRO_ID}")
            # shellcheck disable=SC2153
            DISTRO_NAMES+=("${DISTRO_NAME}")
            DISTRO_FILES+=("${f}")
        fi
    done
}

# Discover distros that provide kernel list update (distro_update_kernel_list).
discover_update_kernel_distros() {
    DISTRO_IDS=()
    DISTRO_NAMES=()
    DISTRO_FILES=()
    local f
    for f in "${DISTROS_DIR}"/*.sh; do
        [[ -f "${f}" ]] || continue
        # shellcheck source=/dev/null
        . "${f}"
        if type distro_update_kernel_list &>/dev/null; then
            # shellcheck disable=SC2153
            DISTRO_IDS+=("${DISTRO_ID}")
            # shellcheck disable=SC2153
            DISTRO_NAMES+=("${DISTRO_NAME}")
            DISTRO_FILES+=("${f}")
        fi
    done
}

run_interactive_tui() {
    trap 'exit 130' INT
    load_config
    if [[ -z "${BASE_IMAGES_DIR:-}" ]] || [[ -z "${OUTPUT_IMAGES_DIR:-}" ]]; then
        gum format "# First run: set paths"
        run_path_wizard
    fi
    while true; do
        choice=$(gum choose \
            "Development VMs (local)" \
            "AWS VMs" \
            "Download a base image" \
            "Update kernel list from repo" \
            "Settings" \
            "Quit" \
            --header "What do you want to do?")
        case "${choice}" in
            "Development VMs (local)") run_env_submenu "local" ;;
            "AWS VMs") run_env_submenu "aws" ;;
            "Download a base image") run_action_download ;;
            "Update kernel list from repo") run_action_update_kernel_list ;;
            "Settings") run_path_wizard ;;
            "Quit"|"") exit 0 ;;
            *) gum format "Unknown choice: ${choice}" ;;
        esac
    done
}

run_env_submenu() {
    local env="$1"
    local header sub
    if [[ "${env}" == "local" ]]; then
        header="Development VMs (local)"
        sub=$(gum choose \
            "Build / customize an image" \
            "Run a VM" \
            --header "${header}")
    else
        header="AWS VMs"
        sub=$(gum choose \
            "Build / customize an image" \
            "Run a VM (test locally)" \
            "Convert to AMI - WIP" \
            "Push AMI to AWS - WIP" \
            --header "${header}")
    fi
    case "${sub}" in
        "Run a VM"*) run_action_run_vm "${env}" ;;
        "Build / customize"*) run_action_build "${env}" ;;
        "Convert to AMI"*) run_action_convert_ami ;;
        "Push AMI to AWS"*) run_action_push_ami ;;
        ""|*) return ;;
    esac
}

# Ask distros (by sourcing each) if they can infer a base image for this VM name.
# Echo path and return 0 if any distro returns a path; else return 1.
infer_base_image_via_distros() {
    local vm_name="${1:?}"
    local base_dir="${2:?}"
    local f result
    for f in "${DISTROS_DIR}"/*.sh; do
        [[ -f "${f}" ]] || continue
        # shellcheck source=/dev/null
        . "${f}"
        if type distro_infer_base_image &>/dev/null && [[ -n "${DISTRO_VM_NAME_PREFIX:-}" ]] && [[ "${vm_name}" == ${DISTRO_VM_NAME_PREFIX}-* ]]; then
            result=$(distro_infer_base_image "${vm_name}" "${base_dir}") || true
            if [[ -n "${result}" ]] && [[ -f "${result}" ]]; then
                echo "${result}"
                return 0
            fi
        fi
    done
    return 1
}

run_action_run_vm() {
    local env="${1:-local}"
    gum format "# Run a VM"
    echo ""
    mkdir -p "${OUTPUT_IMAGES_DIR}"
    local choices=() names=() dirs=() need_bases=() name
    # Names that have a cloud-init ISO (so we don't list the same name again as disk-only)
    local iso_names=()
    # 1) Cloud-init ISOs in output dir (filter by environment suffix)
    local f
    for f in "${OUTPUT_IMAGES_DIR}"/*-${env}-cloud-init.iso; do
        [[ -f "${f}" ]] || continue
        name=$(basename "${f}" -cloud-init.iso)
        iso_names+=("${name}")
        if [[ -f "${OUTPUT_IMAGES_DIR}/${name}.qcow2" ]] || [[ -f "${OUTPUT_IMAGES_DIR}/${name}.img" ]]; then
            choices+=("${name} (cloud-init, ready)")
            names+=("${name}")
            dirs+=("${OUTPUT_IMAGES_DIR}")
            need_bases+=(0)
        else
            choices+=("${name} (cloud-init, need base)")
            names+=("${name}")
            dirs+=("${OUTPUT_IMAGES_DIR}")
            need_bases+=(1)
        fi
    done
    # 2) Disks in output dir without an ISO (filter by environment suffix, no duplicate name)
    local seen added_disk_names=()
    for f in "${OUTPUT_IMAGES_DIR}"/*-${env}.qcow2 "${OUTPUT_IMAGES_DIR}"/*-${env}.img; do
        [[ -f "${f}" ]] || continue
        name=$(basename "${f}" .qcow2)
        name=${name%.img}
        seen=0
        for n in "${iso_names[@]}"; do [[ "${n}" == "${name}" ]] && { seen=1; break; }; done
        [[ "${seen}" -eq 1 ]] && continue
        for n in "${added_disk_names[@]}"; do [[ "${n}" == "${name}" ]] && { seen=1; break; }; done
        [[ "${seen}" -eq 1 ]] && continue
        added_disk_names+=("${name}")
        choices+=("${name} (output)")
        names+=("${name}")
        dirs+=("${OUTPUT_IMAGES_DIR}")
        need_bases+=(0)
    done
    # 3) Legacy images (no -local/-aws suffix) – show only under Development VMs (local)
    if [[ "${env}" == "local" ]]; then
        for f in "${OUTPUT_IMAGES_DIR}"/*-cloud-init.iso; do
            [[ -f "${f}" ]] || continue
            name=$(basename "${f}" -cloud-init.iso)
            [[ "${name}" == *-local || "${name}" == *-aws ]] && continue
            seen=0
            for n in "${iso_names[@]}"; do [[ "${n}" == "${name}" ]] && { seen=1; break; }; done
            [[ "${seen}" -eq 1 ]] && continue
            iso_names+=("${name}")
            if [[ -f "${OUTPUT_IMAGES_DIR}/${name}.qcow2" ]] || [[ -f "${OUTPUT_IMAGES_DIR}/${name}.img" ]]; then
                choices+=("${name} (cloud-init, ready, legacy)")
                names+=("${name}")
                dirs+=("${OUTPUT_IMAGES_DIR}")
                need_bases+=(0)
            else
                choices+=("${name} (cloud-init, need base, legacy)")
                names+=("${name}")
                dirs+=("${OUTPUT_IMAGES_DIR}")
                need_bases+=(1)
            fi
        done
        for f in "${OUTPUT_IMAGES_DIR}"/*.qcow2 "${OUTPUT_IMAGES_DIR}"/*.img; do
            [[ -f "${f}" ]] || continue
            name=$(basename "${f}" .qcow2)
            name=${name%.img}
            [[ "${name}" == *-local || "${name}" == *-aws ]] && continue
            seen=0
            for n in "${iso_names[@]}"; do [[ "${n}" == "${name}" ]] && { seen=1; break; }; done
            [[ "${seen}" -eq 1 ]] && continue
            for n in "${added_disk_names[@]}"; do [[ "${n}" == "${name}" ]] && { seen=1; break; }; done
            [[ "${seen}" -eq 1 ]] && continue
            added_disk_names+=("${name}")
            choices+=("${name} (output, legacy)")
            names+=("${name}")
            dirs+=("${OUTPUT_IMAGES_DIR}")
            need_bases+=(0)
        done
    fi
    # Base images are not listed: running would modify the original. Use "need base" to copy then run.
    if [[ ${#choices[@]} -eq 0 ]]; then
        gum format "No runnable images found. Build a cloud-init ISO or download a base image first."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${choices[@]}" | gum choose --header "Select image to run")
    [[ -z "${choice}" ]] && return
    local i
    for i in "${!choices[@]}"; do
        if [[ "${choices[i]}" != "${choice}" ]]; then
            continue
        fi
        local img="${names[i]}" run_dir="${dirs[i]}" need_base="${need_bases[i]}"
        if [[ "${need_base}" -eq 1 ]]; then
            local src
            src=$(infer_base_image_via_distros "${img}" "${BASE_IMAGES_DIR}") || true
            if [[ -z "${src}" ]] || [[ ! -f "${src}" ]]; then
                # Could not infer: prompt for base image
                local base_options=() base_paths=()
                for f in "${BASE_IMAGES_DIR}"/*.qcow2 "${BASE_IMAGES_DIR}"/*.img; do
                    [[ -f "${f}" ]] || continue
                    base_options+=("$(basename "${f}")")
                    base_paths+=("${f}")
                done
                if [[ ${#base_options[@]} -eq 0 ]]; then
                    gum format "No base images in **${BASE_IMAGES_DIR}**. Download one first."
                    return
                fi
                local base_choice
                base_choice=$(printf '%s\n' "${base_options[@]}" | gum choose --header "Select base image to use as disk")
                [[ -z "${base_choice}" ]] && return
                local j
                for j in "${!base_options[@]}"; do
                    if [[ "${base_options[j]}" == "${base_choice}" ]]; then
                        src="${base_paths[j]}"
                        break
                    fi
                done
            fi
            if [[ -n "${src}" ]] && [[ -f "${src}" ]]; then
                # Prompt for disk size
                local disk_size
                disk_size=$(printf '%s\n' "20G" "40G" "60G" "80G" "100G" | gum choose --header "Disk size for VM")
                [[ -z "${disk_size}" ]] && return
                # Detect backing file format
                local base_fmt="qcow2"
                if command -v qemu-img &>/dev/null; then
                    base_fmt=$(qemu-img info "${src}" 2>/dev/null | awk '/^file format:/{print $3}')
                    base_fmt="${base_fmt:-qcow2}"
                fi
                local dst="${OUTPUT_IMAGES_DIR}/${img}.qcow2"
                local abs_src
                abs_src=$(realpath "${src}")
                gum format "Creating **${disk_size}** overlay disk backed by **$(basename "${src}")**..."
                if ! qemu-img create -f qcow2 -b "${abs_src}" -F "${base_fmt}" "${dst}" "${disk_size}" >/dev/null 2>&1; then
                    print_error "Failed to create overlay disk image."
                    return
                fi
                gum format "  Created **$(basename "${dst}")** (${disk_size}, backed by $(basename "${src}"))"
                echo ""
                run_dir="${OUTPUT_IMAGES_DIR}"
            fi
        fi
        local mode
        mode=$(gum choose "Dev mode (virtiofs, ports)" "Simple run" --header "How to run?")
        [[ -z "${mode}" ]] && return
        if [[ "${mode}" == "Dev mode (virtiofs, ports)" ]]; then
            VM_NAME="${img}" VM_DIR="${run_dir}" "${SCRIPT_DIR}/start-vm-virtiofs.sh" "${img}"
        else
            gum format "Simple run not yet implemented. Use: VM_DIR=${run_dir} ${SCRIPT_DIR}/start-vm-virtiofs.sh ${img}"
        fi
        return
    done
}

run_action_build() {
    local env="${1:-local}"
    gum format "# Build / customize an image"
    echo ""
    local action
    action=$(printf '%s\n' "Pick existing base image" "Download a base image first" | gum choose --header "Build from base or download?")
    [[ -z "${action}" ]] && return
    if [[ "${action}" == "Download a base image first" ]]; then
        run_action_download
        return
    fi
    mkdir -p "${BASE_IMAGES_DIR}"
    # Ask architecture first, then show only base images for that arch
    local arch_choice arch_suffix
    arch_choice=$(printf '%s\n' "x86_64 (amd64)" "aarch64 (arm64)" | gum choose --header "Architecture")
    [[ -z "${arch_choice}" ]] && return
    if [[ "${arch_choice}" == *"x86_64"* ]]; then
        arch_suffix="amd64"
    else
        arch_suffix="arm64"
    fi
    local bases=() labels=() distro_files=() line
    for f in "${DISTROS_DIR}"/*.sh; do
        [[ -f "${f}" ]] || continue
        # shellcheck source=/dev/null
        . "${f}"
        if type distro_list_base_images &>/dev/null; then
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                bases+=("${line%%|*}")
                labels+=("${line#*|}")
                distro_files+=("${f}")
            done < <(distro_list_base_images "${BASE_IMAGES_DIR}" "${arch_suffix}")
        fi
    done
    if [[ ${#bases[@]} -eq 0 ]]; then
        gum format "No base images for **${arch_suffix}** in **${BASE_IMAGES_DIR}**. Download one first or pick another architecture."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${labels[@]}" | gum choose --header "Select release (${arch_suffix})")
    [[ -z "${choice}" ]] && return
    local i base_file selected_distro_file
    for i in "${!labels[@]}"; do
        if [[ "${labels[i]}" == "${choice}" ]]; then
            base_file="${bases[i]}"
            selected_distro_file="${distro_files[i]}"
            break
        fi
    done
    [[ -z "${base_file}" ]] || [[ -z "${selected_distro_file}" ]] && return
    # shellcheck source=/dev/null
    . "${selected_distro_file}"
    local found=0
    if type distro_handles_base &>/dev/null && type distro_build_instructions &>/dev/null; then
        if distro_handles_base "${base_file}"; then
            if type distro_build_prompt_options &>/dev/null; then
                if ! distro_build_prompt_options "${base_file}" "${SCRIPT_DIR}"; then
                    return
                fi
                found=1
                if type distro_build_run &>/dev/null && gum confirm "Run generate-cloud-init and create ISO now?"; then
                    distro_build_run "${base_file}" "${SCRIPT_DIR}" "${OUTPUT_IMAGES_DIR}" "${BASE_IMAGES_DIR}" tui "${env}"
                fi
            else
                distro_build_instructions "${base_file}" "${SCRIPT_DIR}" "${env}"
                found=1
                if type distro_build_run &>/dev/null && gum confirm "Run generate-cloud-init and create ISO now?"; then
                    distro_build_run "${base_file}" "${SCRIPT_DIR}" "${OUTPUT_IMAGES_DIR}" "${BASE_IMAGES_DIR}" tui "${env}"
                fi
            fi
        fi
    fi
    if [[ ${found} -eq 0 ]]; then
        gum format "No distro-specific instructions for **${base_file}**. Use generate-cloud-init.sh and start-vm-virtiofs.sh for your distro; see vm-setup-plan docs."
    fi
}

run_action_download() {
    discover_download_distros
    if [[ ${#DISTRO_NAMES[@]} -eq 0 ]]; then
        gum format "No distro modules with download support found in ${DISTROS_DIR}."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${DISTRO_NAMES[@]}" | gum choose --header "Choose distribution")
    [[ -z "${choice}" ]] && return
    local i
    for i in "${!DISTRO_NAMES[@]}"; do
        if [[ "${DISTRO_NAMES[i]}" == "${choice}" ]]; then
            gum format "# Download – ${choice}"
            echo ""
            # shellcheck source=/dev/null
            . "${DISTRO_FILES[i]}"
            distro_download_run "${BASE_IMAGES_DIR}"
            return
        fi
    done
}

run_action_update_kernel_list() {
    discover_update_kernel_distros
    if [[ ${#DISTRO_NAMES[@]} -eq 0 ]]; then
        gum format "No distro modules with kernel list update support found in ${DISTROS_DIR}."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${DISTRO_NAMES[@]}" | gum choose --header "Update kernel list for")
    [[ -z "${choice}" ]] && return
    local i
    for i in "${!DISTRO_NAMES[@]}"; do
        if [[ "${DISTRO_NAMES[i]}" == "${choice}" ]]; then
            gum format "# Update kernel list – ${choice}"
            echo ""
            # shellcheck source=/dev/null
            . "${DISTRO_FILES[i]}"
            distro_update_kernel_list "${SCRIPT_DIR}"
            return
        fi
    done
}

run_action_convert_ami() {
    gum format "# Convert to AMI (QCOW2 → raw)"
    echo ""
    mkdir -p "${OUTPUT_IMAGES_DIR}"
    local candidates=()
    local f name
    for f in "${OUTPUT_IMAGES_DIR}"/*-aws.qcow2; do
        [[ -f "${f}" ]] || continue
        name=$(basename "${f}" .qcow2)
        candidates+=("${name}")
    done
    if [[ ${#candidates[@]} -eq 0 ]]; then
        gum format "No AWS QCOW2 images found in **${OUTPUT_IMAGES_DIR}**. Build an image under **AWS VMs** first."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${candidates[@]}" | gum choose --header "Select image to convert to raw")
    [[ -z "${choice}" ]] && return
    local raw_path="${OUTPUT_IMAGES_DIR}/${choice}.raw"
    if [[ -f "${raw_path}" ]]; then
        if ! gum confirm "**${choice}.raw** already exists. Overwrite?"; then
            return
        fi
        rm -f "${raw_path}"
    fi
    gum format "Converting **${choice}.qcow2** to raw (this may take a few minutes)..."
    if ! qemu-img convert -f qcow2 -O raw "${OUTPUT_IMAGES_DIR}/${choice}.qcow2" "${raw_path}"; then
        print_error "qemu-img convert failed."
        return
    fi
    gum format "Created **${raw_path}**. Use **Push AMI to AWS** to upload and import."
}

run_action_push_ami() {
    gum format "# Push AMI to AWS"
    echo ""
    if ! command -v aws &>/dev/null; then
        print_error "AWS CLI not found. Install it (e.g. pip install awscli or your distro package)."
        return
    fi
    if ! aws sts get-caller-identity &>/dev/null; then
        print_error "AWS credentials not configured. Run: aws configure"
        return
    fi
    load_config
    if [[ -z "${S3_BUCKET:-}" ]]; then
        gum format "S3 bucket for AMI upload is not set. Configure it in **Settings**."
        return
    fi
    mkdir -p "${OUTPUT_IMAGES_DIR}"
    local candidates=()
    local f name
    for f in "${OUTPUT_IMAGES_DIR}"/*-aws.raw; do
        [[ -f "${f}" ]] || continue
        name=$(basename "${f}" .raw)
        candidates+=("${name}")
    done
    if [[ ${#candidates[@]} -eq 0 ]]; then
        gum format "No AWS raw images found in **${OUTPUT_IMAGES_DIR}**. Use **Convert to AMI** first."
        return
    fi
    local choice
    choice=$(printf '%s\n' "${candidates[@]}" | gum choose --header "Select raw image to push to AWS")
    [[ -z "${choice}" ]] && return
    local raw_path="${OUTPUT_IMAGES_DIR}/${choice}.raw"
    local s3_key="${choice}.raw"
    gum format "Uploading **${choice}.raw** to **s3://${S3_BUCKET}/${s3_key}**..."
    if ! aws s3 cp "${raw_path}" "s3://${S3_BUCKET}/${s3_key}"; then
        print_error "S3 upload failed."
        return
    fi
    gum format "Starting EC2 import task..."
    local task_output
    task_output=$(aws ec2 import-image --disk-containers "Format=raw,UserBucket={S3Bucket=${S3_BUCKET},S3Key=${s3_key}}")
    local import_task_id
    import_task_id=$(echo "${task_output}" | grep -o '"ImportTaskId": "[^"]*"' | cut -d'"' -f4)
    if [[ -z "${import_task_id}" ]]; then
        print_error "Failed to start import task."
        return
    fi
    gum format "Import task **${import_task_id}** started. Waiting for completion..."
    while true; do
        local status
        status=$(aws ec2 describe-import-image-tasks --import-task-ids "${import_task_id}" --query 'ImportImageTasks[0].Status' --output text 2>/dev/null || echo "unknown")
        case "${status}" in
            completed)
                local ami_id
                ami_id=$(aws ec2 describe-import-image-tasks --import-task-ids "${import_task_id}" --query 'ImportImageTasks[0].ImageId' --output text 2>/dev/null)
                gum format "AMI created: **${ami_id}**"
                return
                ;;
            deleted|deleting|cancelled|cancelling)
                print_error "Import task failed or was cancelled: ${status}"
                return
                ;;
        esac
        sleep 10
    done
}

# --- Main ---
load_config

if [[ $# -eq 0 ]]; then
    if ! command -v gum &>/dev/null; then
        exit_gum_required
    fi
    run_interactive_tui
    exit 0
fi

case "${1:-}" in
    run-dev)
        shift
        VM_NAME="${1:-}"
        if [[ -z "${VM_NAME}" ]]; then
            echo "Usage: $0 run-dev <image-name>" >&2
            exit 1
        fi
        VM_DIR="${OUTPUT_IMAGES_DIR:-${HOME}/vms}" "${SCRIPT_DIR}/start-vm-virtiofs.sh" "${VM_NAME}"
        ;;
    download)
        shift
        dl_distro=""
        dl_codename=""
        dl_release=""
        dl_arch="amd64"
        while [[ $# -gt 0 ]]; do
            case "${1}" in
                --distro) dl_distro="${2:-}"; shift 2 ;;
                --codename) dl_codename="${2:-}"; shift 2 ;;
                --release) dl_release="${2:-}"; shift 2 ;;
                --arch) dl_arch="${2:-}"; shift 2 ;;
                *) echo "Unknown flag: ${1}. Use $0 --help" >&2; exit 1 ;;
            esac
        done
        if [[ -z "${dl_distro}" ]]; then
            echo "Usage: $0 download --distro <id> [--codename <name>] [--release <version>] [--arch <arch>]" >&2
            echo "  e.g. $0 download --distro ubuntu --codename noble --arch amd64" >&2
            echo "  or   $0 download --distro ubuntu --release 24.04 --arch amd64" >&2
            exit 1
        fi
        distro_file="${DISTROS_DIR}/${dl_distro}.sh"
        if [[ ! -f "${distro_file}" ]]; then
            echo "Distro not found: ${distro_file}" >&2
            exit 1
        fi
        # shellcheck source=/dev/null
        . "${distro_file}"
        if [[ -z "${dl_codename}" && -n "${dl_release}" ]]; then
            if type distro_release_to_codename &>/dev/null; then
                dl_codename=$(distro_release_to_codename "${dl_release}") || {
                    echo "Unknown release for ${dl_distro}: ${dl_release}. Use --codename." >&2
                    exit 1
                }
            else
                echo "Release mapping for ${dl_distro} not supported. Use --codename." >&2
                exit 1
            fi
        fi
        if [[ -z "${dl_codename}" ]]; then
            echo "Usage: $0 download --distro <id> --codename <name> [--arch <arch>]" >&2
            exit 1
        fi
        if ! type distro_download &>/dev/null; then
            echo "Distro ${dl_distro} does not support download (no distro_download)." >&2
            exit 1
        fi
        echo "Download – ${DISTRO_NAME:-${dl_distro}} (${dl_codename}, ${dl_arch})"
        echo ""
        distro_download "${BASE_IMAGES_DIR}" "${dl_codename}" "${dl_arch}"
        exit $?
        ;;
    --help|-h)
        cat << EOF
Usage: $0 [COMMAND] [FLAGS...]
       $0                    # Interactive TUI (requires gum)
       $0 run-dev <image>    # Run image in dev mode (virtiofs)
       $0 download --distro <id> [--codename <name>|--release <ver>] [--arch <arch>]
       $0 customize ...      # (TODO) Customize image

Interactive mode requires gum: https://github.com/charmbracelet/gum#installation
EOF
        ;;
    *)
        echo "Unknown command: ${1:-}. Use $0 --help" >&2
        exit 1
        ;;
esac
