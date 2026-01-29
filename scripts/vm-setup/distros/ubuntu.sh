# Ubuntu distro module. Source from vm-manager; provides download and build instructions.
# Uses: print_error, print_info, print_step_header, download_with_progress (from vm-manager-lib).
# shellcheck shell=bash
# DISTRO_ID / DISTRO_NAME are read by vm-manager.sh when this file is sourced
# shellcheck disable=SC2034
DISTRO_ID="ubuntu"
DISTRO_NAME="Ubuntu"
# VM names from our build look like ubuntu-20.04-aws-5.15.0-1084-x86_64; prefix for "Run a VM" inference
# shellcheck disable=SC2034
DISTRO_VM_NAME_PREFIX="ubuntu"

# LTS releases first, then latest (most recent available)
UBUNTU_RELEASE_LABELS=("20.04 LTS (focal)" "22.04 LTS (jammy)" "24.04 LTS (noble)" "Latest (25.04 plucky)")
UBUNTU_RELEASE_CODENAMES=("focal" "jammy" "noble" "plucky")
UBUNTU_ARCH_LABELS=("x86_64 (amd64)" "aarch64 (arm64)")
UBUNTU_ARCH_NAMES=("amd64" "arm64")
# Kernel flavours to try when updating from repo (GA + cloud only; no HWE/lowlatency)
# plucky has no linux-image-*-gke in repo
UBUNTU_KERNEL_FLAVOURS_GENERIC=(generic aws azure gcp gke)
UBUNTU_KERNEL_FLAVOURS_FOCAL=(generic aws azure gcp gke)
UBUNTU_KERNEL_FLAVOURS_JAMMY=(generic aws azure gcp gke)
UBUNTU_KERNEL_FLAVOURS_NOBLE=(generic aws azure gcp gke)
UBUNTU_KERNEL_FLAVOURS_PLUCKY=(generic aws azure gcp)
# GPG key for SHA256SUMS signature verification (override with env var if the key changes)
UBUNTU_IMAGE_SIGNING_KEY="${UBUNTU_IMAGE_SIGNING_KEY:-D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81}"

# Get remote Last-Modified as epoch (empty if unavailable). Uses curl or wget.
_ubuntu_remote_epoch() {
    local url="${1:?}"
    local raw
    if command -v curl &>/dev/null; then
        raw=$(curl -sI -L "${url}" 2>/dev/null | grep -i '^last-modified:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    elif command -v wget &>/dev/null; then
        raw=$(wget --spider -S "${url}" 2>&1 | grep -i '^[[:space:]]*last-modified:' | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    fi
    if [[ -z "${raw}" ]]; then return; fi
    # GNU date (Linux) or BSD date (macOS)
    date -d "${raw}" +%s 2>/dev/null || date -j -f "%a, %d %b %Y %H:%M:%S %Z" "${raw}" +%s 2>/dev/null
}

# Internal: fetch SHA256SUMS and SHA256SUMS.gpg. No output.
_ubuntu_fetch_checksums() {
    local base_url="${1:?}"
    local sums_file="${2:?}"
    local sums_gpg="${3:?}"
    if command -v curl &>/dev/null; then
        curl -fsSL -o "${sums_file}" "${base_url}/SHA256SUMS" && curl -fsSL -o "${sums_gpg}" "${base_url}/SHA256SUMS.gpg"
    else
        wget -q -O "${sums_file}" "${base_url}/SHA256SUMS" && wget -q -O "${sums_gpg}" "${base_url}/SHA256SUMS.gpg"
    fi
}

# Internal: run gpg verify. Returns 0 if OK. Tries to import key if missing.
_ubuntu_verify_gpg() {
    local sums_gpg="${1:?}"
    local sums_file="${2:?}"
    if ! command -v gpg &>/dev/null; then
        return 1
    fi
    if gpg --keyid-format long --verify "${sums_gpg}" "${sums_file}" 2>/dev/null; then
        return 0
    fi
    gpg --keyserver keyserver.ubuntu.com --recv-keys "${UBUNTU_IMAGE_SIGNING_KEY}" 2>/dev/null
    gpg --keyid-format long --verify "${sums_gpg}" "${sums_file}" 2>/dev/null
}

# Internal: run sha256sum -c. Returns 0 if OK.
_ubuntu_verify_sha256() {
    local base_dir="${1:?}"
    local codename="${2:?}"
    command -v sha256sum &>/dev/null || return 1
    (cd "${base_dir}" && sha256sum -c --ignore-missing "${codename}-current-SHA256SUMS" >/dev/null 2>&1)
}

# Core download + verify (no TUI). For flag-based CLI. Uses echo only.
distro_download() {
    local base_dir="${1:?}"
    local codename="${2:?}"
    local arch="${3:?}"
    local filename="${codename}-server-cloudimg-${arch}.img"
    local url="https://cloud-images.ubuntu.com/${codename}/current/${filename}"
    local dest="${base_dir}/${filename}"
    local base_url="https://cloud-images.ubuntu.com/${codename}/current"
    local sums_file="${base_dir}/${codename}-current-SHA256SUMS"
    local sums_gpg="${base_dir}/${codename}-current-SHA256SUMS.gpg"
    mkdir -p "${base_dir}"

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo "Error: Neither wget nor curl found." >&2
        return 1
    fi

    download_with_progress "${url}" "${dest}.tmp"
    local status=$?
    if [[ ${status} -ne 0 ]]; then
        echo "Download failed (exit ${status}). Check URL: ${url}" >&2
        return "${status}"
    fi
    mv "${dest}.tmp" "${dest}"
    echo "Downloaded to ${dest}"

    _ubuntu_fetch_checksums "${base_url}" "${sums_file}" "${sums_gpg}" || true
    if [[ ! -f "${sums_file}" ]] || [[ ! -f "${sums_gpg}" ]]; then
        echo "Error: Failed to fetch checksum files." >&2
        return 1
    fi

    if _ubuntu_verify_gpg "${sums_gpg}" "${sums_file}"; then
        echo "GPG signature OK (SHA256SUMS signed by Ubuntu)."
    else
        echo "Warning: GPG verification failed. Continuing with checksum only." >&2
    fi
    if _ubuntu_verify_sha256 "${base_dir}" "${codename}"; then
        echo "Image: OK"
        echo "Checksum OK. Verified."
    else
        echo "Error: Checksum verification failed. Image may be corrupted." >&2
        return 1
    fi
    echo "Saved to ${dest}. Checksum files kept: ${sums_file}, ${sums_gpg}"
    return 0
}

# TUI: prompt release/arch, then run download+verify with step headers, spin, aligned gum output.
distro_download_run() {
    local base_dir="${1:?}"
    local release_choice arch_choice codename arch i
    release_choice=$(printf '%s\n' "${UBUNTU_RELEASE_LABELS[@]}" | gum choose --header "Ubuntu release")
    [[ -z "${release_choice}" ]] && return 1
    codename=""
    for i in "${!UBUNTU_RELEASE_LABELS[@]}"; do
        if [[ "${UBUNTU_RELEASE_LABELS[i]}" == "${release_choice}" ]]; then
            codename="${UBUNTU_RELEASE_CODENAMES[i]}"
            break
        fi
    done
    [[ -z "${codename}" ]] && return 1
    arch_choice=$(printf '%s\n' "${UBUNTU_ARCH_LABELS[@]}" | gum choose --header "Architecture")
    [[ -z "${arch_choice}" ]] && return 1
    arch=""
    for i in "${!UBUNTU_ARCH_LABELS[@]}"; do
        if [[ "${UBUNTU_ARCH_LABELS[i]}" == "${arch_choice}" ]]; then
            arch="${UBUNTU_ARCH_NAMES[i]}"
            break
        fi
    done
    [[ -z "${arch}" ]] && return 1

    local filename="${codename}-server-cloudimg-${arch}.img"
    local dest="${base_dir}/${filename}"
    local url="https://cloud-images.ubuntu.com/${codename}/current/${filename}"
    local base_url="https://cloud-images.ubuntu.com/${codename}/current"
    local sums_file="${base_dir}/${codename}-current-SHA256SUMS"
    local sums_gpg="${base_dir}/${codename}-current-SHA256SUMS.gpg"

    if [[ -f "${dest}" ]]; then
        local remote_epoch local_epoch
        remote_epoch=$(_ubuntu_remote_epoch "${url}")
        local_epoch=""
        if [[ -n "${remote_epoch}" ]] && command -v stat &>/dev/null; then
            local_epoch=$(stat -c %Y "${dest}" 2>/dev/null || stat -f %m "${dest}" 2>/dev/null)
        fi
        if [[ -n "${remote_epoch}" && -n "${local_epoch}" ]]; then
            if (( remote_epoch > local_epoch )); then
                if ! gum confirm "A newer image is available online. Download?"; then
                    return 0
                fi
            else
                if ! gum confirm "Local image appears up to date. Re-download anyway?"; then
                    return 0
                fi
            fi
        else
            if ! gum confirm "File already exists: ${dest}. Re-download?"; then
                return 0
            fi
        fi
    fi

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        print_error "Neither wget nor curl found. Install one to download images."
        return 1
    fi

    mkdir -p "${base_dir}"

    print_step_header "1. Download"
    gum format "Downloading **${filename}**..."
    download_with_progress "${url}" "${dest}.tmp"
    local status=$?
    if [[ ${status} -ne 0 ]]; then
        print_error "Download failed (exit ${status}). Check URL: ${url}"
        return "${status}"
    fi
    mv "${dest}.tmp" "${dest}"
    gum format "Downloaded to **${dest}**"
    echo ""

    print_step_header "2. Verify"
    if command -v curl &>/dev/null; then
        gum spin --title "Fetching checksums..." -- bash -c "curl -fsSL -o '${sums_file}' '${base_url}/SHA256SUMS' && curl -fsSL -o '${sums_gpg}' '${base_url}/SHA256SUMS.gpg'"
    else
        gum spin --title "Fetching checksums..." -- bash -c "wget -q -O '${sums_file}' '${base_url}/SHA256SUMS' && wget -q -O '${sums_gpg}' '${base_url}/SHA256SUMS.gpg'"
    fi
    if [[ ! -f "${sums_file}" ]] || [[ ! -f "${sums_gpg}" ]]; then
        print_error "Failed to fetch checksum files."
        return 1
    fi
    gum format "Verifying signature and checksum..."
    if _ubuntu_verify_gpg "${sums_gpg}" "${sums_file}"; then
        gum format "  GPG signature OK (SHA256SUMS signed by Ubuntu)."
    else
        print_info "Importing Ubuntu image signing key..."
        if _ubuntu_verify_gpg "${sums_gpg}" "${sums_file}"; then
            gum format "  GPG signature OK (SHA256SUMS signed by Ubuntu)."
        else
            print_error "GPG verification failed. To verify manually: gpg --keyserver keyserver.ubuntu.com --recv-keys ${UBUNTU_IMAGE_SIGNING_KEY}. Continuing with checksum only."
        fi
    fi
    if ! command -v sha256sum &>/dev/null; then
        print_error "sha256sum not found. Cannot verify image."
        return 1
    fi
    if _ubuntu_verify_sha256 "${base_dir}" "${codename}"; then
        gum format "  Image: OK"
        gum format "  Checksum OK. Verified."
    else
        print_error "Checksum verification failed. Image may be corrupted."
        return 1
    fi
    gum format "  Saved to **${dest}**. Checksum files kept: **${sums_file}**, **${sums_gpg}**"
    echo ""
    return 0
}

distro_handles_base() {
    local base_file="${1:?}"
    [[ "${base_file}" == *-server-cloudimg-*.img || "${base_file}" == *-server-cloudimg-*.qcow2 ]]
}

# Echo "filename|label" per base image in base_dir for arch_suffix (e.g. amd64). Used by Build flow.
distro_list_base_images() {
    local base_dir="${1:?}"
    local arch_suffix="${2:?}"
    local f name codename label
    for f in "${base_dir}"/*-server-cloudimg-${arch_suffix}.img "${base_dir}"/*-server-cloudimg-${arch_suffix}.qcow2; do
        [[ -f "${f}" ]] || continue
        name=$(basename "${f}")
        codename="${name%-server-cloudimg-*}"
        case "${codename}" in
            focal)  label="20.04 LTS (focal)" ;;
            jammy)  label="22.04 LTS (jammy)" ;;
            noble)  label="24.04 LTS (noble)" ;;
            plucky) label="25.04 (plucky)" ;;
            *)      label="${codename}" ;;
        esac
        echo "${name}|${label}"
    done
}

# Map release (e.g. 24.04) to codename for CLI download. Echo codename and return 0, or return 1.
distro_release_to_codename() {
    local codename
    codename=$(_ubuntu_codename_from_version "${1:?}")
    [[ -z "${codename}" ]] && return 1
    echo "${codename}"
    return 0
}

# Prompt for architecture, kernel flavour, and kernel version (from repo). Sets _ubuntu_build_* for use by distro_build_instructions and distro_build_run.
# Returns 0 if user completed the flow, 1 if cancelled. Call before distro_build_instructions in the TUI build flow.
distro_build_prompt_options() {
    local base_file="${1:?}"
    local script_dir="${2:?}"
    if ! _ubuntu_base_to_version_arch "${base_file}"; then
        print_error "Could not parse base filename: ${base_file}"
        return 1
    fi
    local version="${_ubuntu_build_version}"
    local default_arch="${_ubuntu_build_arch}"
    local codename
    codename=$(_ubuntu_codename_from_version "${version}")
    [[ -z "${codename}" ]] && codename="jammy"

    # Arch already implied by base image choice in vm-manager
    _ubuntu_build_arch="${default_arch}"
    local arch_name
    arch_name=$(_ubuntu_arch_to_binary "${default_arch}")

    # Kernel flavour (GA + HWE for this release)
    local flavours flavour_choice
    flavours=($(_ubuntu_flavours_for_codename "${codename}"))
    flavour_choice=$(printf '%s\n' "${flavours[@]}" | gum choose --header "Kernel flavour")
    [[ -z "${flavour_choice}" ]] && return 1
    _ubuntu_build_flavour="${flavour_choice}"

    # Use cached kernel list for this release/arch/flavour; fetch only if missing (no prompt).
    if ! _ubuntu_fetch_kernel_versions "${script_dir}" "${codename}" "${arch_name}" "${_ubuntu_build_flavour}"; then
        print_error "No kernel versions from repo. Enter version manually (see Ubuntu package list for latest)."
        local suggested
        suggested=$(_ubuntu_default_kernel "${version}")
        _ubuntu_build_kernel=$(gum input --header "Kernel version" --placeholder "${suggested}" --value "${suggested}")
        [[ -z "${_ubuntu_build_kernel}" ]] && _ubuntu_build_kernel="${suggested}"
        return 0
    fi

    local cache_file="${HOME}/.tracee-vm-manager/cache/kernel-versions/${codename}-${arch_name}-${_ubuntu_build_flavour}.txt"
    local versions=()
    while IFS= read -r line; do
        [[ -n "${line}" ]] && versions+=("${line}")
    done <"${cache_file}"
    if [[ ${#versions[@]} -eq 0 ]]; then
        local suggested
        suggested=$(_ubuntu_default_kernel "${version}")
        _ubuntu_build_kernel=$(gum input --header "Kernel version" --placeholder "${suggested}" --value "${suggested}")
        [[ -z "${_ubuntu_build_kernel}" ]] && _ubuntu_build_kernel="${suggested}"
        return 0
    fi
    # Newest last in file (sort -V); show newest first in chooser
    local i
    local kernel_choice
    kernel_choice=$(for i in $(seq $((${#versions[@]} - 1)) -1 0); do echo "${versions[i]}"; done | gum choose --header "Kernel version (from repo)")
    [[ -z "${kernel_choice}" ]] && return 1
    _ubuntu_build_kernel="${kernel_choice}"
    return 0
}

# Parse Ubuntu base filename (e.g. jammy-server-cloudimg-arm64.img) to version and arch for generate-cloud-init.
# Sets _ubuntu_build_version and _ubuntu_build_arch (e.g. 22.04, aarch64). Returns 0 if parsed.
_ubuntu_base_to_version_arch() {
    local base_file="${1:?}"
    local base_name="${base_file%.*}"
    # ...-server-cloudimg-<arch>  -> codename is first segment, arch is last
    if [[ ! "${base_name}" =~ ^(.+)-server-cloudimg-(.+)$ ]]; then
        return 1
    fi
    local codename="${BASH_REMATCH[1]}"
    local arch="${BASH_REMATCH[2]}"
    case "${codename}" in
        focal) _ubuntu_build_version="20.04" ;;
        jammy) _ubuntu_build_version="22.04" ;;
        noble) _ubuntu_build_version="24.04" ;;
        plucky) _ubuntu_build_version="25.04" ;;
        *) return 1 ;;
    esac
    case "${arch}" in
        amd64) _ubuntu_build_arch="x86_64" ;;
        arm64) _ubuntu_build_arch="aarch64" ;;
        *) _ubuntu_build_arch="${arch}" ;;
    esac
    return 0
}

# Fallback kernel version when repo is unavailable. Not kept in sync with Ubuntu; newer
# kernels appear in the repo—use "Update kernel list from repo" or enter version manually.
_ubuntu_default_kernel() {
    local version="${1:?}"
    case "${version}" in
        20.04) echo "5.15.0-91" ;;
        22.04) echo "5.19.0-50" ;;
        24.04) echo "6.11.0-29" ;;
        25.04) echo "6.11.0-29" ;;
        *) echo "6.11.0-29" ;;
    esac
}

# Codename from Ubuntu version (e.g. 22.04 -> jammy)
_ubuntu_codename_from_version() {
    case "${1:?}" in
        20.04) echo "focal" ;;
        22.04) echo "jammy" ;;
        24.04) echo "noble" ;;
        25.04) echo "plucky" ;;
        *) echo "" ;;
    esac
}

# Infer base image path from Ubuntu-style VM name (e.g. ubuntu-20.04-aws-5.15.0-1084-x86_64).
# Echo path to existing base file and return 0, or return 1.
distro_infer_base_image() {
    local vm_name="${1:?}"
    local base_dir="${2:?}"
    local version arch_suffix codename base_file
    # Allow optional -local or -aws suffix (environment-aware image names)
    if [[ ! "${vm_name}" =~ ^ubuntu-([0-9]+\.[0-9]+)-.+-((x86_64|aarch64))(-(local|aws))?$ ]]; then
        return 1
    fi
    version="${BASH_REMATCH[1]}"
    arch_suffix="${BASH_REMATCH[2]}"
    case "${arch_suffix}" in
        x86_64) arch_suffix="amd64" ;;
        aarch64) arch_suffix="arm64" ;;
    esac
    codename=$(_ubuntu_codename_from_version "${version}")
    [[ -z "${codename}" ]] && return 1
    for base_file in "${base_dir}/${codename}-server-cloudimg-${arch_suffix}.img" "${base_dir}/${codename}-server-cloudimg-${arch_suffix}.qcow2"; do
        if [[ -f "${base_file}" ]]; then
            echo "${base_file}"
            return 0
        fi
    done
    return 1
}

# Suite for -updates repo (e.g. jammy -> jammy-updates)
_ubuntu_suite_for_updates() {
    local codename="${1:?}"
    echo "${codename}-updates"
}

# Our arch name to Ubuntu binary arch (x86_64 -> amd64, aarch64 -> arm64)
_ubuntu_arch_to_binary() {
    case "${1:?}" in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) echo "${1}" ;;
    esac
}

# Return list of kernel flavours to try for a given codename (GA + HWE).
_ubuntu_flavours_for_codename() {
    case "${1:?}" in
        focal)  echo "${UBUNTU_KERNEL_FLAVOURS_FOCAL[@]}" ;;
        jammy)  echo "${UBUNTU_KERNEL_FLAVOURS_JAMMY[@]}" ;;
        noble)  echo "${UBUNTU_KERNEL_FLAVOURS_NOBLE[@]}" ;;
        plucky) echo "${UBUNTU_KERNEL_FLAVOURS_PLUCKY[@]}" ;;
        *)      echo "${UBUNTU_KERNEL_FLAVOURS_GENERIC[@]}" ;;
    esac
}

# Main-menu entry: update kernel list from repo for all releases, archs, and flavours (no prompts).
# Runs each fetch under a gum spin with status (release/arch/flavour).
distro_update_kernel_list() {
    local script_dir="${1:?}"
    local codename arch_name flavour ok=0 fail=0
    local flavours
    gum format "Updating kernel lists from Ubuntu repo (all releases, archs, flavours)..."
    echo ""
    for codename in "${UBUNTU_RELEASE_CODENAMES[@]}"; do
        flavours=($(_ubuntu_flavours_for_codename "${codename}"))
        for arch_name in "${UBUNTU_ARCH_NAMES[@]}"; do
            for flavour in "${flavours[@]}"; do
                if gum spin --title "${codename}/${arch_name}/${flavour}..." -- bash -c '
                    . "$1/vm-manager-lib.sh"
                    . "$1/distros/ubuntu.sh"
                    _ubuntu_fetch_kernel_versions "$1" "$2" "$3" "$4" --update
                ' _ "${script_dir}" "${codename}" "${arch_name}" "${flavour}"; then
                    ((ok++)) || true
                else
                    ((fail++)) || true
                fi
            done
        done
    done
    echo ""
    gum format "Updated **${ok}** kernel lists."
    [[ ${fail} -gt 0 ]] && gum format "Failed: **${fail}** (release/arch/flavour not in repo or fetch error)."
    echo ""
    return 0
}

# Base URL for Ubuntu package lists: arm64/armhf etc. are on ports.ubuntu.com.
_ubuntu_packages_base_url() {
    local binary_arch="${1:?}"
    case "${binary_arch}" in
        amd64|i386) echo "http://archive.ubuntu.com/ubuntu" ;;
        *) echo "http://ports.ubuntu.com/ubuntu-ports" ;;
    esac
}

# Fetch available kernel versions from Ubuntu repo for codename/arch/flavour.
# Writes one version per line to cache file, sorted (newest last). Uses -updates suite.
# arm64/armhf use ports.ubuntu.com; amd64 uses archive.ubuntu.com.
# Returns 0 on success. If --update or cache missing, fetches; otherwise uses cache.
_ubuntu_fetch_kernel_versions() {
    local script_dir="${1:?}"
    local codename="${2:?}"
    local binary_arch="${3:?}"
    local flavour="${4:?}"
    local do_update=false
    [[ "${5:-}" == "--update" ]] && do_update=true
    local suite
    suite=$(_ubuntu_suite_for_updates "${codename}")
    local cache_dir="${HOME}/.tracee-vm-manager/cache/kernel-versions"
    local cache_file="${cache_dir}/${codename}-${binary_arch}-${flavour}.txt"
    mkdir -p "${cache_dir}"

    if [[ "${do_update}" != "true" && -f "${cache_file}" && -s "${cache_file}" ]]; then
        return 0
    fi

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        print_error "Neither curl nor wget found. Cannot fetch kernel list."
        return 1
    fi

    local base_url
    base_url=$(_ubuntu_packages_base_url "${binary_arch}")
    local url="${base_url}/dists/${suite}/main/binary-${binary_arch}/Packages.gz"
    local tmp_packages
    tmp_packages=$(mktemp -t "ubuntu-Packages.XXXXXXXX.gz")
    if command -v curl &>/dev/null; then
        curl -fsSL -o "${tmp_packages}" "${url}" 2>/dev/null || true
    else
        wget -q -O "${tmp_packages}" "${url}" 2>/dev/null || true
    fi
    if [[ ! -s "${tmp_packages}" ]]; then
        url="${base_url}/dists/${codename}/main/binary-${binary_arch}/Packages.gz"
        if command -v curl &>/dev/null; then
            curl -fsSL -o "${tmp_packages}" "${url}" 2>/dev/null || true
        else
            wget -q -O "${tmp_packages}" "${url}" 2>/dev/null || true
        fi
    fi
    if [[ ! -s "${tmp_packages}" ]]; then
        rm -f "${tmp_packages}"
        print_error "${codename}/${binary_arch}/${flavour}: Failed to fetch Packages.gz (tried ${base_url}; network or ${suite} unavailable)."
        return 1
    fi
    if [[ -n "${TRACEE_VM_DEBUG:-}" ]]; then
        echo "  [debug] ${codename}/${binary_arch}/${flavour}: fetched ${url}" >&2
        echo "  [debug] sample Package lines matching linux-image.*${flavour}:" >&2
        gunzip -c "${tmp_packages}" 2>/dev/null | grep -E "^Package: linux-image.*${flavour}" | head -5 >&2
    fi
    local tmp_txt
    tmp_txt=$(mktemp -t "ubuntu-Packages.XXXXXXXX.txt")
    gunzip -c "${tmp_packages}" 2>/dev/null >"${tmp_txt}"
    rm -f "${tmp_packages}"
    # Parse Package: linux-image-X.Y.Z-N-flavour or linux-image-unsigned-X.Y.Z-N-flavour -> X.Y.Z-N (portable sed)
    sed -n \
        -e 's/^Package: linux-image-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-[0-9][0-9]*\)-'"${flavour}"'$/\1/p' \
        -e 's/^Package: linux-image-unsigned-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-[0-9][0-9]*\)-'"${flavour}"'$/\1/p' \
        <"${tmp_txt}" | sort -uV >"${cache_file}.tmp"
    # HWE flavours are meta-packages (Package: linux-image-generic-hwe-22.04) with no version in name; extract ABI from Version: (e.g. 6.8.0-94.96~22.04.1 -> 6.8.0-94)
    if [[ ! -s "${cache_file}.tmp" && "${flavour}" == *"-hwe-"* ]]; then
        awk -v flav="${flavour}" '
            $0 == "Package: linux-image-" flav { in_meta=1; next }
            in_meta && /^$/ { in_meta=0; next }
            in_meta && /^Version:/ { v=$2; gsub(/~.*$/,"",v); gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); split(v,a,"-"); split(a[2],b,"."); if (a[1]!="" && b[1]!="") print a[1]"-"b[1]; in_meta=0; next }
            in_meta && /^Depends:/ { for (i=2;i<=NF;i++) if ($i ~ /^\(=/) { v=($i=="(=" && i<NF) ? $(i+1) : $i; gsub(/[()=,]|~.*$/,"",v); gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); split(v,a,"-"); split(a[2],b,"."); if (a[1]!="" && b[1]!="") print a[1]"-"b[1]; in_meta=0; exit } }
        ' "${tmp_txt}" | sort -uV >>"${cache_file}.tmp"
    fi
    if [[ -n "${TRACEE_VM_DEBUG:-}" && ! -s "${cache_file}.tmp" ]]; then
        echo "  [debug] no lines matched sed pattern for flavour=${flavour}; Package lines containing 'linux-image' and '${flavour}':" >&2
        grep "linux-image" "${tmp_txt}" | grep "${flavour}" | head -5 >&2
    fi
    rm -f "${tmp_txt}"
    if [[ -s "${cache_file}.tmp" ]]; then
        mv "${cache_file}.tmp" "${cache_file}"
        return 0
    fi
    rm -f "${cache_file}.tmp"
    print_error "${codename}/${binary_arch}/${flavour}: No linux-image-*-${flavour} packages in repo (flavour not offered for this release/arch)."
    return 1
}

distro_build_instructions() {
    local base_file="${1:?}"
    local script_dir="${2:?}"
    local env="${3:-local}"
    if ! _ubuntu_base_to_version_arch "${base_file}"; then
        gum format "Could not parse **${base_file}** (expected codename-server-cloudimg-arch.img). Use generate-cloud-init.sh manually."
        return
    fi
    local version="${_ubuntu_build_version}"
    local arch="${_ubuntu_build_arch}"
    local flavour="${_ubuntu_build_flavour:-generic}"
    local kernel="${_ubuntu_build_kernel:-}"
    [[ -z "${kernel}" ]] && kernel=$(_ubuntu_default_kernel "${version}")
    local image_name="ubuntu-${version}-${flavour}-${kernel}-${arch}-${env}"
    gum format "To customize **${base_file}** (Ubuntu ${version}, ${arch}, kernel ${flavour} ${kernel}, env ${env}):" \
        "1. Generate cloud-init: \`${script_dir}/generate-cloud-init.sh -d ubuntu -v ${version} -f ${flavour} -k ${kernel} -a ${arch} -e ${env}\`" \
        "2. Create ISO: \`cloud-localds ${script_dir}/generated/${image_name}-cloud-init.iso ${script_dir}/generated/${image_name}-user-data.yaml ${script_dir}/generated/${image_name}-meta-data.yaml\`" \
        "3. Copy ISO and base image to VM dir, then run VM. See vm-setup-plan/WORKFLOW-CUSTOM-IMAGE.md for full steps."
}

# Run generate-cloud-init and cloud-localds for the given base.
# Usage: distro_build_run base_file script_dir output_dir base_images_dir [tui] [env]
# If 5th arg is "tui", use gum spin for each step and gum format for output; otherwise echo (CLI).
# 6th arg env: local or aws (default local).
distro_build_run() {
    local base_file="${1:?}"
    local script_dir="${2:?}"
    local output_dir="${3:?}"
    local base_images_dir="${4:?}"
    local use_tui="${5:-}"
    local env="${6:-local}"
    if ! _ubuntu_base_to_version_arch "${base_file}"; then
        if [[ "${use_tui}" == "tui" ]]; then
            print_error "Could not parse base filename: ${base_file}"
        else
            echo "Error: Could not parse base filename: ${base_file}" >&2
        fi
        return 1
    fi
    local version="${_ubuntu_build_version}"
    local arch="${_ubuntu_build_arch}"
    local flavour="${_ubuntu_build_flavour:-generic}"
    local kernel="${_ubuntu_build_kernel:-}"
    [[ -z "${kernel}" ]] && kernel=$(_ubuntu_default_kernel "${version}")
    local image_name="ubuntu-${version}-${flavour}-${kernel}-${arch}-${env}"
    local gen_dir="${output_dir}"
    mkdir -p "${gen_dir}"

    # Check for existing cloud-init ISO and disk image
    local existing_iso="${gen_dir}/${image_name}-cloud-init.iso"
    local existing_disk=""
    if [[ -f "${gen_dir}/${image_name}.img" ]]; then
        existing_disk="${gen_dir}/${image_name}.img"
    elif [[ -f "${gen_dir}/${image_name}.qcow2" ]]; then
        existing_disk="${gen_dir}/${image_name}.qcow2"
    fi

    if [[ -f "${existing_iso}" ]] || [[ -n "${existing_disk}" ]]; then
        if [[ "${use_tui}" == "tui" ]]; then
            echo ""
            gum format "## Existing files detected for **${image_name}**"
            echo ""
            [[ -f "${existing_iso}" ]] && gum format "  - Cloud-init ISO: **$(basename "${existing_iso}")**"
            [[ -n "${existing_disk}" ]] && gum format "  - Disk image: **$(basename "${existing_disk}")**"
            echo ""
            if [[ -n "${existing_disk}" ]]; then
                gum format "> The disk image will be **removed** so the next run starts fresh from the base image with the new cloud-init ISO."
                echo ""
            fi
            if ! gum confirm "Rebuild cloud-init and remove existing disk?"; then
                gum format "Build cancelled."
                return 0
            fi
            # Remove existing disk image so next run copies fresh from base
            if [[ -n "${existing_disk}" ]]; then
                rm -f "${existing_disk}"
                gum format "  Removed **$(basename "${existing_disk}")**"
                echo ""
            fi
        else
            if [[ -f "${existing_iso}" ]]; then
                echo "Existing cloud-init ISO found: ${existing_iso}"
            fi
            if [[ -n "${existing_disk}" ]]; then
                echo "Existing disk image found: ${existing_disk}"
                echo "The disk image will be removed so the next run starts fresh."
                rm -f "${existing_disk}"
                echo "Removed: ${existing_disk}"
            fi
        fi
    fi

    # Prompt for SSH public key to inject into the VM
    local ssh_key_arg=""
    if [[ "${use_tui}" == "tui" ]]; then
        local -a ssh_keys=()
        local key_file
        for key_file in ~/.ssh/*.pub; do
            [[ -f "${key_file}" ]] && ssh_keys+=("${key_file}")
        done
        if [[ ${#ssh_keys[@]} -gt 0 ]]; then
            local chosen_key
            chosen_key=$(printf '%s\n' "${ssh_keys[@]}" | gum choose --header "SSH public key to inject into VM")
            if [[ -n "${chosen_key}" ]]; then
                ssh_key_arg="-s ${chosen_key}"
                gum format "  SSH key: **$(basename "${chosen_key}")**"
                echo ""
            fi
        else
            gum format "> No SSH public keys found in ~/.ssh/. VM will use password auth only."
            echo ""
        fi
    else
        # CLI: use default key resolution in generate-cloud-init.sh
        :
    fi

    if [[ "${use_tui}" == "tui" ]]; then
        print_step_header "1. Generate cloud-init"
        # shellcheck disable=SC2086
        if ! gum spin --title "Generating cloud-init config..." -- "${script_dir}/generate-cloud-init.sh" -d ubuntu -v "${version}" -f "${flavour}" -k "${kernel}" -a "${arch}" -e "${env}" ${ssh_key_arg} -o "${gen_dir}" >/dev/null 2>&1; then
            print_error "generate-cloud-init.sh failed."
            return 1
        fi
        gum format "  Generated **${image_name}-user-data.yaml** and **${image_name}-meta-data.yaml**"
        echo ""
        print_step_header "2. Create ISO"
        if ! command -v cloud-localds &>/dev/null; then
            print_error "cloud-localds not found. Install cloud-utils (or cloud-init package)."
            return 1
        fi
        local iso_err
        iso_err=$(mktemp -t "cloud-localds.XXXXXXXX.err")
        if ! (cd "${gen_dir}" && cloud-localds "${image_name}-cloud-init.iso" "${image_name}-user-data.yaml" "${image_name}-meta-data.yaml" </dev/null) 2>"${iso_err}"; then
            print_error "Failed to create cloud-init ISO."
            [[ -s "${iso_err}" ]] && cat "${iso_err}" >&2
            rm -f "${iso_err}"
            return 1
        fi
        rm -f "${iso_err}"
        gum format "  Created **${image_name}-cloud-init.iso**"
        echo ""
    else
        # shellcheck disable=SC2086
        if ! "${script_dir}/generate-cloud-init.sh" -d ubuntu -v "${version}" -f "${flavour}" -k "${kernel}" -a "${arch}" -e "${env}" ${ssh_key_arg} -o "${gen_dir}" >/dev/null 2>&1; then
            echo "Error: generate-cloud-init.sh failed." >&2
            return 1
        fi
        if ! command -v cloud-localds &>/dev/null; then
            echo "Error: cloud-localds not found. Install cloud-utils (or cloud-init package)." >&2
            return 1
        fi
        (cd "${gen_dir}" && cloud-localds "${image_name}-cloud-init.iso" "${image_name}-user-data.yaml" "${image_name}-meta-data.yaml" < /dev/null) >/dev/null 2>&1
        if [[ ! -f "${gen_dir}/${image_name}-cloud-init.iso" ]]; then
            echo "Error: Failed to create cloud-init ISO." >&2
            return 1
        fi
        echo "Generated: ${gen_dir}/${image_name}-cloud-init.iso"
        echo "Next: Copy base image to ${output_dir}, then run the VM with start-vm-virtiofs.sh (see WORKFLOW-CUSTOM-IMAGE.md)."
    fi
    return 0
}
