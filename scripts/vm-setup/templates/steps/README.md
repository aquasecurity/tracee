# Cloud-Init Template Steps

This directory contains reusable steps that are shared across multiple distro-specific templates to follow the DRY (Don't Repeat Yourself) principle.

## Available Steps

### `download-scripts.yaml`
**Purpose:** Downloads all installation scripts and libraries from the Tracee GitHub repository.

**What it does:**
- Creates directory structure in `/tmp/tracee/`
- Downloads all `lib*.sh` files
- Downloads installation scripts (clang, golang, deps, ami-tooling)
- Downloads GPG keys
- Makes scripts executable

**Used by:** All distro templates (ubuntu, centos, alpine)

**Variables used:**
- `${DISTRO}` - For distro-specific install-deps script

---

### `install-tools.yaml`
**Purpose:** Installs all dependencies via `install-deps-${DISTRO}.sh`.

**What it does:**
- Runs the distro-specific `install-deps-${DISTRO}.sh` script
- The script installs: base packages, Go, Clang, Go tools, Docker
- Configures user environment (Go paths, Docker group) for `USER_NAME`
- Installs AWS/AMI tooling (if `ENVIRONMENT=aws`)

**Used by:** All distro templates (ubuntu, centos, alpine)

**Variables used:**
- `${DISTRO}` - Selects the appropriate install-deps script
- `${ENVIRONMENT}` - For conditional AWS tooling installation
- `${USER_NAME}` - Passed to install-deps script for user environment configuration

---

### `setup-virtfs.yaml`
**Purpose:** Configures automatic mounting of virtfs shares for local development.

**What it does:**
- Creates `/mnt/tracee` and `/mnt/libbpfgo` directories
- Sets ownership to appropriate user
- Creates systemd mount units for auto-mounting
- Enables mount units for boot

**Used by:** All distro templates (ubuntu, centos, alpine)

**Variables used:**
- `${USERNAME}` - Dynamically set by generator (ubuntu/ec2-user/alpine)
- `${ENVIRONMENT}` - Only runs if `ENVIRONMENT=local`

---

### `finalize.yaml`
**Purpose:** Final steps before reboot.

**What it does:**
- Creates `/tmp/tracee-vm-init.done` marker file
- Logs completion timestamp
- Schedules reboot to activate new kernel

**Used by:** All distro templates (ubuntu, centos, alpine)

**Variables used:**
- None

---

## How Steps Work

### 1. Templates Use Placeholders

Distro-specific templates contain placeholders:

```yaml
runcmd:
  - echo "Starting setup..." | tee -a /var/log/tracee-vm-init.log
  
  # DOWNLOAD_SCRIPTS_PLACEHOLDER
  
  # Install kernel
  # KERNEL_SCRIPT_PLACEHOLDER
  
  # INSTALL_TOOLS_PLACEHOLDER
  
  # SETUP_VIRTFS_PLACEHOLDER
  
  # FINALIZE_PLACEHOLDER
```

### 2. Generator Script Injects Steps

`generate-cloud-init.sh` reads step files and replaces placeholders:

```bash
# Read steps
DOWNLOAD_SCRIPTS=$(cat "${SCRIPT_DIR}/templates/steps/download-scripts.yaml")
INSTALL_TOOLS=$(cat "${SCRIPT_DIR}/templates/partials/install-tools.yaml")
SETUP_VIRTFS=$(cat "${SCRIPT_DIR}/templates/partials/setup-virtfs.yaml")
FINALIZE=$(cat "${SCRIPT_DIR}/templates/partials/finalize.yaml")

# Replace variables in steps
SETUP_VIRTFS="${SETUP_VIRTFS//\$\{USERNAME\}/${USERNAME}}"

# Inject into template
USER_DATA="${USER_DATA//  # DOWNLOAD_SCRIPTS_PLACEHOLDER/$DOWNLOAD_SCRIPTS}"
USER_DATA="${USER_DATA//  # INSTALL_TOOLS_PLACEHOLDER/$INSTALL_TOOLS}"
USER_DATA="${USER_DATA//  # SETUP_VIRTFS_PLACEHOLDER/$SETUP_VIRTFS}"
USER_DATA="${USER_DATA//  # FINALIZE_PLACEHOLDER/$FINALIZE}"
```

### 3. Generated YAML Contains Full Content

The final generated `user-data.yaml` has all steps expanded with proper indentation and variable substitution.

## Benefits of Using Steps

### 1. DRY Principle ✓
- Common logic written once
- Reduces duplication across templates
- Single source of truth for shared sections

### 2. Maintainability ✓
- Update partial once, affects all templates
- Easier to spot and fix bugs
- Clear separation of concerns

### 3. Consistency ✓
- All distros use identical script download logic
- All distros use identical tool installation logic
- Reduces drift between distro templates

### 4. Readability ✓
- Distro templates focus on distro-specific differences
- Common logic abstracted away
- Easier to see what makes each distro unique

## Distro-Specific vs Step Logic

### What Stays in Distro Templates

**Package manager operations:**
- `apt-get` vs `dnf` vs `apk`
- Lock file checking (`dpkg` vs `rpm`)
- System updates

**User configuration:**
- Username (ubuntu vs ec2-user vs alpine)
- Groups (sudo vs wheel)
- Default packages

**Service management:**
- SSH service name (ssh vs sshd)
- Init system (systemd vs OpenRC)

### What Goes in Steps

**Script downloads:**
- Same GitHub URLs for all distros
- Same directory structure
- Same lib files

**Tool installation:**
- Uses distro-agnostic scripts
- Conditional logic handled in scripts themselves
- Same workflow for all distros

**Virtfs setup:**
- Same systemd mount units
- Only username differs (handled by variable)

**Finalization:**
- Same marker file
- Same reboot command

## Adding New Steps

To add a new reusable section:

1. **Create step file:**
   ```bash
   touch templates/steps/my-new-section.yaml
   ```

2. **Add placeholder to templates:**
   ```yaml
   # MY_NEW_SECTION_PLACEHOLDER
   ```

3. **Update generator script:**
   ```bash
   MY_NEW_SECTION=$(cat "${SCRIPT_DIR}/templates/steps/my-new-section.yaml")
   USER_DATA="${USER_DATA//  # MY_NEW_SECTION_PLACEHOLDER/$MY_NEW_SECTION}"
   ```

4. **Test with all distros:**
   ```bash
   ./generate-cloud-init.sh -d ubuntu ...
   ./generate-cloud-init.sh -d centos ...
   ./generate-cloud-init.sh -d alpine ...
   ```

## Variable Substitution in Steps

Steps can use template variables:

- `${DISTRO}` - Distribution name
- `${VERSION}` - Distribution version
- `${KERNEL_FLAVOR}` - Kernel flavor
- `${KERNEL_VERSION}` - Kernel version
- `${ENVIRONMENT}` - Environment type (local/aws)
- `${USERNAME}` - Distro-specific username (dynamically set)

Variables are replaced by the generator script before injection.

## Best Practices

1. **Keep steps distro-agnostic**
   - Don't reference specific package managers
   - Use conditionals for distro-specific behavior

2. **Use clear placeholder names**
   - Name should describe what the partial does
   - Use ALL_CAPS with underscores

3. **Document step purpose**
   - Add comments at the top
   - Explain any complex logic

4. **Test across all distros**
   - Ensure partial works for ubuntu, centos, alpine
   - Verify variable substitution works correctly

5. **Keep steps focused**
   - One step = one responsibility
   - Don't combine unrelated functionality
