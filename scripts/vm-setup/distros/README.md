# Distro modules for VM Manager

Each file in this directory is a **sourced** script (not executed directly). The orchestrator `vm-manager.sh` discovers distros and sources the chosen module when needed.

## Contract

A distro script must define:

- **`DISTRO_ID`** – Identifier used in menus and for sourcing (e.g. `ubuntu`).
- **`DISTRO_NAME`** – Human-readable name (e.g. `Ubuntu`).

Optional functions (if missing, the manager skips or shows a generic message):

- **`distro_download base_dir codename arch`** – **Core logic (no TUI).** Download and verify image into `base_dir`. Uses only `echo` for output so it works from flag-based CLI. Return 0 on success. If present, `$0 download --distro <id> --codename <name> --arch <arch>` will call this.
- **`distro_download_run base_dir`** – **TUI.** Interactive download: prompt release/arch (with gum), then call `distro_download`. Return 0 on success.
- **`distro_handles_base base_file`** – Return 0 if this distro “handles” the given base filename (e.g. Ubuntu cloud image pattern). Used to show distro-specific build instructions.
- **`distro_build_instructions base_file script_dir`** – Print customize/build steps for this base image (e.g. generate-cloud-init, cloud-localds). Called when user picks “Build” and selected a base file this distro handles.

- **`distro_build_run base_file script_dir output_dir base_images_dir`** – **Core logic (no TUI).** Run generate-cloud-init and cloud-localds; write ISO to `script_dir/generated/`. If present, the TUI offers "Run these steps now?" after instructions.

- **`distro_infer_base_image vm_name base_dir`** – **(Optional.)** If this distro can infer a base image path from a VM name (e.g. from a cloud-init ISO name), echo the absolute path and return 0; otherwise return 1. Used by "Run a VM" when an ISO needs a base disk. If the distro provides this, it should also set **`DISTRO_VM_NAME_PREFIX`** (e.g. `ubuntu`) so the manager only calls this when `vm_name` starts with `${DISTRO_VM_NAME_PREFIX}-`.

- **`distro_list_base_images base_dir arch_suffix`** – **(Optional.)** Echo one line per base image this distro handles for the given arch: `filename|label`. Used by the Build flow to show a release picker (e.g. "20.04 LTS (focal)").

- **`distro_release_to_codename release`** – **(Optional.)** For CLI `download --distro <id> --release <ver>`: echo the distro’s codename for that release and return 0, or return 1 if unknown. E.g. Ubuntu `24.04` → `noble`.

## Discovery

The manager lists distros by sourcing each `distros/*.sh` and reading `DISTRO_ID` and `DISTRO_NAME`. Only distros that define `distro_download_run` are offered in the Download menu.

## Example: stub for “coming soon”

```bash
DISTRO_ID="centos"
DISTRO_NAME="CentOS (coming soon)"
# No distro_download_run – manager will not offer in download list, or can show “not implemented”.
```
