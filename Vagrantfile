# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Tracee Development VM - QEMU Provider Configuration
#
# OVERVIEW:
#   Cross-platform development environment for Tracee security toolkit
#   Uses QEMU with hardware acceleration for optimal performance
#
# SUPPORTED PLATFORMS:
#   - Linux (KVM acceleration on x86_64/aarch64)
#   - macOS (HVF acceleration on Intel/Apple Silicon)
#
# REQUIREMENTS:
#   - QEMU installed on host system
#   - vagrant-qemu plugin: vagrant plugin install vagrant-qemu
#   - Hardware acceleration: KVM on Linux, HVF on macOS (optional, falls back to TCG)
#
# USAGE:
#   Basic:     vagrant up
#   Custom:    VM_TYPE=test VM_CPUS=4 VM_MEM=4 vagrant up
#              VM_ACCEL=tcg vagrant up (software emulation)
#   Change:    vagrant halt && VM_ACCEL=kvm vagrant up (acceleration change)
#
# FEATURES:
#   - 9p filesystem for real-time bidirectional file sync (with bindfs on macOS, direct mount on Linux)
#   - Automatic port forwarding with collision detection and auto-correction
#   - Hardware acceleration when available (KVM/HVF)
#   - Auto-detection of QEMU directory based on host OS
#   - Configurable CPU, memory, and VM type via environment variables

require 'etc'
require 'fileutils'

host_os = case
when Vagrant::Util::Platform.linux?
  "Linux"
when Vagrant::Util::Platform.darwin?
  "Darwin"
else
  puts "ERROR: Host OS is not supported."
  abort
end

arch = case `uname -m`.strip
when "x86_64", "amd64"
  "amd64"
when "aarch64", "arm64"
  "arm64"
else
  puts "ERROR: Architecture is not supported."
  abort
end

# VM_TYPE is used to determine the environment (dev or test) to provision the VM for.
# By default, the VM is provisioned for the "dev" environment.
# To provision the VM for the "test" environment, set the VM_TYPE environment variable to "test".
# Example: VM_TYPE=test vagrant up
vm_type = ENV["VM_TYPE"]
if vm_type.nil? || vm_type.empty?
  vm_type = "dev"
end

if vm_type != "dev" && vm_type != 'test'
  puts "ERROR: Invalid VM_TYPE value. Only 'dev' or 'test' values are allowed."
  abort
end

vm_name = "tracee-#{vm_type}-vm"

vm_cpus = ENV["VM_CPUS"]
if vm_cpus.nil? || vm_cpus.empty?
  vm_cpus = Etc.nprocessors / 2
end

# in GB
vm_mem = ENV["VM_MEM"]
if vm_mem.nil? || vm_mem.empty?
  vm_mem = "8"
end

vm_user = "vagrant"
vm_synced_folder = "/#{vm_user}"

# Detect hardware acceleration availability for optimal performance
# Supports Linux (KVM) and Darwin/macOS (HVF) on amd64 and arm64 architectures
def detect_hardware_acceleration(host_os, arch)
  case host_os
  when "Linux"
    # Check for KVM support
    if File.exist?('/dev/kvm') && File.readable?('/dev/kvm')
      # Additional check: verify KVM module is loaded
      kvm_loaded = system("lsmod | grep -q kvm 2>/dev/null")
      if kvm_loaded
        return { accel: "kvm", cpu: "host", note: "Using KVM acceleration with host CPU (optimal performance)" }
      end
    end
  when "Darwin"
    # Check for Hypervisor Framework (HVF) on macOS
    # HVF is available on macOS 10.10+ with Intel CPUs or Apple Silicon
    hvf_available = system("sysctl -n kern.hv_support 2>/dev/null | grep -q 1")
    if hvf_available
      return { accel: "hvf", cpu: "host", note: "Using HVF acceleration with host CPU (optimal performance)" }
    end
  end
  
  # Fallback to software emulation
  emulated_cpu = arch == "amd64" ? "qemu64" : "cortex-a57"
  return { 
    accel: "tcg", 
    cpu: emulated_cpu, 
    note: "Using software emulation (TCG) - slower but more compatible" 
  }
end

# Detect the best acceleration method for this system
hw_accel = detect_hardware_acceleration(host_os, arch)

# Detect QEMU directory based on host OS
qemu_dir = case host_os
when "Darwin"
  # macOS: Check for Apple Silicon Homebrew first, fallback to Intel Homebrew
  if File.directory?("/opt/homebrew/share/qemu")
    "/opt/homebrew/share/qemu"  # Apple Silicon Homebrew
  elsif File.directory?("/usr/local/share/qemu")
    "/usr/local/share/qemu"     # Intel Homebrew
  else
    nil  # Let vagrant-qemu auto-detect
  end
when "Linux"
  # Linux: Check common QEMU installation paths
  if File.directory?("/usr/share/qemu")
    "/usr/share/qemu"           # Standard Linux path
  elsif File.directory?("/usr/local/share/qemu")
    "/usr/local/share/qemu"     # Custom/compiled installation
  else
    nil  # Let vagrant-qemu auto-detect
  end
end

# Allow override via environment variable for testing/debugging
# Example: VM_ACCEL=tcg vagrant up (to force software emulation)
if ENV["VM_ACCEL"]
  vm_accel_override = ENV["VM_ACCEL"]
  
  # Validate that the specified acceleration is compatible with the host OS
  case vm_accel_override
  when "kvm"
    if host_os != "Linux"
      puts "❌ ERROR: KVM acceleration is only available on Linux hosts"
      puts "   Current host OS: #{host_os}"
      puts "   Available accelerations for macOS: hvf, tcg"
      exit 1
    end
  when "hvf"
    if host_os != "Darwin"
      puts "❌ ERROR: HVF (Hypervisor Framework) acceleration is only available on macOS hosts"
      puts "   Current host OS: #{host_os}"
      puts "   Available accelerations for Linux: kvm, tcg"
      exit 1
    end
  when "tcg"
    # TCG (software emulation) is available on both Linux and macOS
  else
    puts "❌ ERROR: Invalid acceleration type '#{vm_accel_override}'"
    puts "   Valid options: kvm (Linux only), hvf (macOS only), tcg (both platforms)"
    exit 1
  end

  hw_accel[:accel] = vm_accel_override
  hw_accel[:cpu] = vm_accel_override == "tcg" ? (arch == "amd64" ? "qemu64" : "cortex-a57") : "host"
  hw_accel[:note] = "Using manually specified acceleration: #{vm_accel_override}"
end

# Display configuration information
puts "=== Configuration ==="
puts "Host OS: #{host_os}"
puts "Architecture: #{arch}"
puts "VM Type: #{vm_type}"
puts "CPUs: #{vm_cpus}"
puts "Memory: #{vm_mem}G"
puts "Acceleration: #{hw_accel[:accel].upcase}"
puts "CPU Model: #{hw_accel[:cpu]}"
puts "QEMU Directory: #{qemu_dir || 'Auto-detect'}"
puts "Note: #{hw_accel[:note]}"
puts "Performance: #{hw_accel[:accel] == 'tcg' ? 'Slower (software emulation)' : 'Optimal (hardware acceleration)'}"
puts ""
puts "Available Environment Variables:"
puts "  VM_TYPE=<dev|test>          - Set VM environment type (default: dev)"
puts "  VM_CPUS=<number>            - Set number of CPUs (default: #{Etc.nprocessors / 2})"
puts "  VM_MEM=<number>             - Set memory in GB (default: 8)"
case host_os
when "Linux"
  puts "  VM_ACCEL=<kvm|tcg>          - Force specific acceleration type (Linux: kvm=fast, tcg=slow)"
when "Darwin"
  puts "  VM_ACCEL=<hvf|tcg>          - Force specific acceleration type (macOS: hvf=fast, tcg=slow)"
end
puts ""
puts "💡 Changing Acceleration:"
puts "  To change acceleration after VM creation: 'vagrant halt && VM_ACCEL=<type> vagrant up'"
puts "  Note: 'vagrant reload' does NOT apply acceleration changes - use halt/up cycle"
puts ""
puts "Examples:"
puts "  VM_TYPE=test VM_CPUS=4 VM_MEM=4 vagrant up"
puts "  VM_ACCEL=tcg vagrant up"
puts "====================="

provider_settings = lambda do |prov, name|
  if name == "qemu"
    prov.name = vm_name
    prov.cpus = vm_cpus
    prov.memory = "#{vm_mem}G"  # Use G suffix as shown in the documentation
    # Set QEMU directory (detected earlier based on host OS)
    prov.qemu_dir = qemu_dir if qemu_dir
    prov.arch = arch == "amd64" ? "x86_64" : "aarch64"

    # Configure machine type, acceleration and 9p filesystem based on detected capabilities
    case hw_accel[:accel]
    when "kvm"
      # For KVM acceleration on Linux
      prov.machine = arch == "amd64" ? "q35,accel=kvm" : "virt,accel=kvm"
      prov.cpu = "host"
      prov.extra_qemu_args = %w(-virtfs local,path=.,mount_tag=shared,security_model=mapped-xattr,fmode=0644,dmode=0755)
    when "hvf"
      # For HVF acceleration on macOS
      prov.machine = arch == "amd64" ? "q35,accel=hvf" : "virt,accel=hvf"
      prov.cpu = "host"
      prov.extra_qemu_args = %w(-virtfs local,path=.,mount_tag=shared,security_model=mapped-xattr,fmode=0644,dmode=0755)
    when "tcg"
      # For software emulation
      prov.machine = arch == "amd64" ? "q35" : "virt"
      prov.cpu = hw_accel[:cpu]  # Use emulated CPU
      prov.extra_qemu_args = %w(-accel tcg,thread=multi -virtfs local,path=.,mount_tag=shared,security_model=mapped-xattr,fmode=0644,dmode=0755)
    end

    prov.net_device = "virtio-net-pci"
    prov.disk_interface = "virtio"
    prov.graphics_type = "none"
    prov.no_daemonize = true
  end
  
end

Vagrant.configure("2") do |config|
  config.ssh.extra_args = ["-t", "cd #{vm_synced_folder}; bash --login"]

  # Use 9p filesystem with optimized settings for better symlink handling
  # This provides bidirectional real-time file sharing
  config.vm.synced_folder ".", "#{vm_synced_folder}", disabled: true

  # define the machine with the dynamically set vm_name
  config.vm.define vm_name do |vm_config|
    # Using QEMU provider for cross-platform support
    vm_config.vm.box = "cloud-image/ubuntu-24.04"

    vm_config.vm.provider "qemu" do |qe|
      provider_settings.call(qe, "qemu")
    end

    # network settings
    vm_config.vm.hostname = vm_name

    # NOTE: QEMU provider translates these port forwarding configurations into QEMU hostfwd parameters
    # Port forwarding works through QEMU's user networking with automatic collision handling
    # Ports are auto-corrected when conflicts occur - requested ports may differ from actual ports
    # Use 'vagrant ssh-config' for SSH port or 'ps aux | grep qemu-system | grep hostfwd' for all ports
    #
    # Port forwarding configuration (actual ports may vary due to auto-correction):
    vm_config.vm.network "forwarded_port", guest: 9090, host: 9090, auto_correct: true # Prometheus server
    vm_config.vm.network "forwarded_port", guest: 3366, host: 3366, auto_correct: true # Tracee HTTP server (/metrics, /healthz, /debug/pprof)
    vm_config.vm.network "forwarded_port", guest: 3000, host: 3000, auto_correct: true # Grafana dashboard UI
    vm_config.vm.network "forwarded_port", guest: 8000, host: 8000, auto_correct: true # MkDocs documentation server (/tracee)

    if vm_type == "dev"
      # Forward MicroK8s dashboard to access it on the host at https://localhost:10443
      #
      # To access the Kubernetes dashboard from the host run the following command:
      #     kubectl port-forward --address 0.0.0.0 -n kube-system service/kubernetes-dashboard 10443:443
      #
      # To sign in use the token retrieved with
      #     token=$(microk8s kubectl -n kube-system get secret | grep default-token | cut -d " " -f1)
      #     kubectl -n kube-system describe secret $token
      #
      # TIP For Google Chrome you may allow insecure TLS connections at chrome://flags/#allow-insecure-localhost
      vm_config.vm.network "forwarded_port", guest: 10443, host: 10443, auto_correct: true
    end

    vm_config.vm.provision "shell", privileged: true, reboot: true, inline: <<-SHELL
      set -e

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      echo ">>> Setting up 9p filesystem mount with symlink handling"

      # Install 9p support
      apt-get update
      apt-get install -y 9mount

      SYNCED_FOLDER="#{vm_synced_folder}"
      HOST_OS="#{host_os}"

      echo "Detected host OS: ${HOST_OS}"

      if [ "${HOST_OS}" = "Darwin" ]; then
        echo "Using Darwin-specific bindfs approach for ownership mapping"
        # Install bindfs for ownership mapping (needed on macOS)
        echo "Installing bindfs for ownership mapping"
        apt-get install -y bindfs

        # Step 1: Mount 9p filesystem to temporary location first
        TEMP_MOUNT="/mnt/shared"
        mkdir -p ${TEMP_MOUNT}
        echo "Step 1: Mounting 9p filesystem to ${TEMP_MOUNT}"
        mount -t 9p -o trans=virtio,version=9p2000.L shared ${TEMP_MOUNT} || echo "Note: 9p mount may already be active"

        # Check initial permissions (should show host UID and group)
        echo "Initial permissions at ${TEMP_MOUNT}:"
        ls -la ${TEMP_MOUNT} | head -3

        # Step 2: Use bindfs to create properly mapped view at final location
        mkdir -p ${SYNCED_FOLDER}
        echo "Step 2: Creating bindfs mapping from ${TEMP_MOUNT} to ${SYNCED_FOLDER}"
        echo "Mapping: host UID → guest UID 1000 (vagrant), host GID → guest GID 1000 (vagrant)"
        # First check if /vagrant is already mounted and unmount if needed
        if mountpoint -q ${SYNCED_FOLDER}; then
          echo "Unmounting existing bindfs at ${SYNCED_FOLDER}"
          umount ${SYNCED_FOLDER}
        fi

        # Ensure any existing mount is cleaned up first
        umount ${SYNCED_FOLDER} 2>/dev/null || true
        bindfs --force-user=1000 --force-group=1000 -o allow_other ${TEMP_MOUNT} ${SYNCED_FOLDER}

        # Verify corrected permissions and that files are visible
        echo "Final permissions at ${SYNCED_FOLDER}:"
        ls -la ${SYNCED_FOLDER} | head -3
        echo "Verifying files are visible:"
        ls ${SYNCED_FOLDER} | head -3 || echo "Warning: No files visible in bindfs mount"

        # Add 9p mount to fstab (but not bindfs - systemd service will handle that)
        if ! grep -q "shared" /etc/fstab; then
          echo "shared ${TEMP_MOUNT} 9p trans=virtio,version=9p2000.L,_netdev 0 0" >> /etc/fstab
        fi

        # Create systemd service for bindfs mapping (inspired by Franz Wong's guide)
        echo "Creating systemd service for bindfs mapping"
        cat > /etc/systemd/system/bindfs-vagrant.service << EOF
[Unit]
Description=Map uid and gid of /vagrant with bindfs
After=vagrant.mount
Requires=vagrant.mount

[Service]
Type=forking
ExecStartPre=/bin/mkdir -p ${SYNCED_FOLDER}
ExecStartPre=/bin/bash -c 'umount ${SYNCED_FOLDER} 2>/dev/null || true'
ExecStart=/usr/bin/bindfs --force-user=1000 --force-group=1000 -o allow_other ${TEMP_MOUNT} ${SYNCED_FOLDER}
ExecStartPost=/bin/bash -c 'ls ${SYNCED_FOLDER} | head -3 || echo "Warning: No files visible in bindfs"'

[Install]
WantedBy=multi-user.target
EOF

        # Create systemd mount unit for /mnt/shared
        echo "Creating systemd mount unit for 9p filesystem"
        cat > /etc/systemd/system/mnt-shared.mount << EOF
[Unit]
Description=9p shared filesystem mount
After=vagrant.target

[Mount]
What=shared
Where=${TEMP_MOUNT}
Type=9p
Options=trans=virtio,version=9p2000.L,_netdev

[Install]
WantedBy=multi-user.target
EOF

        # Create systemd mount unit for /vagrant
        echo "Creating systemd mount unit for /vagrant"
        cat > /etc/systemd/system/vagrant.mount << EOF
[Unit]
Description=Vagrant shared folder
After=mnt-shared.mount
Requires=mnt-shared.mount

[Mount]
What=${TEMP_MOUNT}
Where=${SYNCED_FOLDER}
Type=fuse.bindfs
Options=force-user=1000,force-group=1000,allow_other

[Install]
WantedBy=multi-user.target
EOF

        # Enable and start systemd services
        systemctl daemon-reload
        systemctl enable mnt-shared.mount
        systemctl enable vagrant.mount
        systemctl enable bindfs-vagrant.service

        echo "Starting systemd mount services"
        systemctl start mnt-shared.mount
        systemctl start vagrant.mount || echo "Note: vagrant.mount may conflict with current mount"

        echo "9p filesystem with bindfs ownership mapping complete"
      else
        echo "Using Linux-specific direct 9p mount approach"

        # On Linux, direct 9p mount with dfltuid/dfltgid should work correctly
        mkdir -p ${SYNCED_FOLDER}
        echo "Mounting 9p filesystem directly to ${SYNCED_FOLDER}"
        mount -t 9p -o trans=virtio,version=9p2000.L,dfltuid=1000,dfltgid=1000,uname=vagrant,access=any shared ${SYNCED_FOLDER} || echo "Note: 9p mount may already be active"

        # Add direct 9p mount to fstab
        if ! grep -q "shared" /etc/fstab; then
          echo "shared ${SYNCED_FOLDER} 9p trans=virtio,version=9p2000.L,dfltuid=1000,dfltgid=1000,uname=vagrant,access=any,_netdev 0 0" >> /etc/fstab
        fi

        echo "9p filesystem direct mount complete"
      fi

      echo ">>> 9p filesystem setup complete"
    SHELL

    # Kernel upgrade - early placement ensures new kernel is available for development tools
    vm_config.vm.provision "shell", privileged: true, reboot: true, inline: <<-SHELL
      set -e

      KERNEL_VERSION="6.8.0-1038-aws"
      USER="#{vm_user}"

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      echo ">>> Kernel version: $(uname -r)"

      echo ">>> Installing kernel ${KERNEL_VERSION}"
      apt-get update
      apt-get install --yes \
        dkms \
        linux-image-${KERNEL_VERSION} \
        linux-headers-${KERNEL_VERSION} \
        linux-modules-${KERNEL_VERSION} \
        linux-tools-${KERNEL_VERSION}
    SHELL

    # System updates + reboot to load updated binaries
    vm_config.vm.provision "shell", privileged: true, reboot: true, inline: <<-SHELL
      set -e

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      echo ">>> Kernel version: $(uname -r)"

      echo ">>> Updating system packages"
      apt-get update
      apt-get --yes upgrade
    SHELL

    # Main provisioning after reboot with updated system
    vm_config.vm.provision "shell", privileged: true, inline: <<-SHELL
      set -e

      ARCH="#{arch}"
      USER="#{vm_user}"
      HOME="/home/#{vm_user}"
      KUBECTL_VERSION="v1.29"
      VM_TYPE="#{vm_type}"
      SYNCED_FOLDER="#{vm_synced_folder}"

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      #
      # build environment for tracee
      #

      echo ">>> Installing build environment for tracee"

      # Install Tracee dependencies using the installation script
      INSTALL_UBUNTU_DEPS="${SYNCED_FOLDER}/scripts/installation/install-deps-ubuntu.sh"
      
      echo "Running Tracee dependency installation script"
      ${INSTALL_UBUNTU_DEPS}

      # Set up Go paths for user environment
      GOBIN_PATH=/usr/local/go/bin
      echo "export PATH=${PATH}:${GOBIN_PATH}" >> ${HOME}/.profile
      # integration tests run as root, so go needs to be in root's path as well
      echo "export PATH=${PATH}:${GOBIN_PATH}" >> $HOME/.bashrc
      # sudo needs to be able to find go as well
      echo "Defaults secure_path=\"${PATH}:${GOBIN_PATH}\"" >> /etc/sudoers.d/${USER}

      echo ">>> Setting Go cache permissions"
      mkdir -p ${HOME}/.cache/go-build
      chown -R ${USER}:${USER} ${HOME}/.cache
      chmod -R u+w ${HOME}/.cache

      # python environment setup for Ubuntu 24.04
      echo ">>> Installing python tools"
      apt-get install --yes python3 python3-pip python3-venv

      # Ubuntu 24.04 uses externally managed Python environment (PEP 668)
      # Create a virtual environment for Python packages instead of system-wide installation
      sudo -u ${USER} python3 -m venv ${HOME}/.venv
      sudo -u ${USER} ${HOME}/.venv/bin/pip install docker boto3 psutil jmespath

      # Add virtual environment to user's profile
      echo 'export PATH="${HOME}/.venv/bin:${PATH}"' >> ${HOME}/.profile
      echo 'alias pip="${HOME}/.venv/bin/pip"' >> ${HOME}/.profile
      echo 'alias python="${HOME}/.venv/bin/python"' >> ${HOME}/.profile

      # other tools
      echo ">>> Installing other tools"
      apt-get install --yes jq

      # install MicroK8s and related tools if VM_TYPE is "dev"
      if [ "${VM_TYPE}" = "dev" ]; then
        echo ">>> Installing MicroK8s and related tools"

        # microk8s
        echo ">>> Installing microk8s"
        snap install microk8s --classic
        microk8s status --wait-ready
        usermod -a -G microk8s ${USER}
        microk8s enable hostpath-storage dns dashboard

        mkdir -p ${HOME}/.kube/
        microk8s kubectl config view --raw > ${HOME}/.kube/config
        chmod 600 ${HOME}/.kube/config
        chown ${USER}:${USER} ${HOME}/.kube/config

        # kubectl
        echo ">>> Installing kubectl"
        apt-get install -y apt-transport-https ca-certificates curl
        curl -fsSL https://pkgs.k8s.io/core:/stable:/${KUBECTL_VERSION}/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
        chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
        echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBECTL_VERSION}/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list
        chmod 644 /etc/apt/sources.list.d/kubernetes.list
        apt-get update
        apt-get install --yes kubectl
        echo 'source <(kubectl completion bash)' >> ${HOME}/.profile

        # helm
        echo ">>> Installing helm"
        snap install helm --classic
        echo 'source <(helm completion bash)' >> ${HOME}/.profile
      fi

      #
      # docker
      #

      echo ">>> Installing docker"
      apt-get install --yes docker.io
      usermod -aG docker ${USER}

      echo ">>> Build environment setup completed"

    SHELL

    # Additional provisioning as the vagrant user
    vm_config.vm.provision "shell", privileged: false, inline: <<-SHELL
      set -e

      SYNCED_FOLDER="#{vm_synced_folder}"

      echo ">>> Setting up user-specific environment for Ubuntu 24.04"

      # Ensure Go cache directory exists and has proper permissions
      mkdir -p ~/.cache/go-build

      # Source the profile to get the updated PATH
      source ~/.profile

      # Test that Go works properly for the user
      if command -v go >/dev/null 2>&1; then
        echo "Go version: $(go version)"
        echo "GOROOT: $(go env GOROOT)"
        echo "GOCACHE: $(go env GOCACHE)"
      else
        echo "ERROR: Go not found in PATH"
      fi

      # Test that Python virtual environment works
      if [ -f ~/.venv/bin/python ]; then
        echo "Python virtual environment: $(~/.venv/bin/python --version)"
        echo "Pip version: $(~/.venv/bin/pip --version)"
      else
        echo "ERROR: Python virtual environment not found"
      fi

      # This fixes git ownership issue - configure safe directory for shared folder
      echo ">>> Configuring git safe directory"
      git config --global --add safe.directory "${SYNCED_FOLDER}"

      echo ">>> User environment setup completed"
    SHELL

    share_provisioning = lambda do |vm_config, name|
      if name == "qemu"
        # Ensure 9p mount is active after reboots
        vm_config.vm.provision "shell", run: "always", privileged: true, inline: <<-SHELL
          set +e

          SYNCED_FOLDER="#{vm_synced_folder}"
          USER="#{vm_user}"

          HOST_OS="#{host_os}"
          echo ">>> Ensuring 9p mount is active (Host OS: ${HOST_OS})"
          
          if [ "${HOST_OS}" = "Darwin" ]; then
            echo "Verifying Darwin-specific systemd mounts"

            # Let systemd handle the mounts properly with dependencies
            systemctl daemon-reload
            systemctl start mnt-shared.mount || echo "mnt-shared.mount may already be active"
            systemctl start vagrant.mount || echo "vagrant.mount may already be active"

            # Check mount status
            echo "Mount status:"
            systemctl status mnt-shared.mount --no-pager || true
            systemctl status vagrant.mount --no-pager || true

            echo ">>> Darwin systemd mount verification complete"
          else
            echo "Verifying Linux-specific direct 9p mount"

            # Check if direct 9p mount exists at /vagrant
            if ! mountpoint -q ${SYNCED_FOLDER}; then
              echo "Re-mounting 9p filesystem directly to ${SYNCED_FOLDER}"
              mkdir -p ${SYNCED_FOLDER}
              mount -t 9p -o trans=virtio,version=9p2000.L,dfltuid=1000,dfltgid=1000,uname=vagrant,access=any shared ${SYNCED_FOLDER} || echo "9p mount failed"
            fi

            echo ">>> Linux direct mount verification complete"
          fi

          # Verify files are visible (common for both approaches)
          echo "Verifying /vagrant shows files:"
          ls ${SYNCED_FOLDER} | head -3 || echo "No files visible - mount may need time"
        SHELL
      end
    end

    # Always use QEMU share provisioning
    share_provisioning.call(vm_config, "qemu")
    
    # Final step: provide usage instructions
    vm_config.vm.provision "shell", privileged: false, inline: <<-SHELL
      echo ">>> VM provisioning complete!"
      echo ""
      echo "🔗 SSH Access:"
      echo "  Vagrant:   VM_TYPE=#{vm_type} vagrant ssh"
      echo ""
      echo "🚀 Build Tracee:"
      echo "  cd #{vm_synced_folder}"
      echo "  make all"
      echo ""
      echo "🌐 Port Forwarding:"
      echo "  Ports are automatically configured with collision detection."
      echo "  To see actual forwarded ports:"
      echo "    vagrant ssh-config  # Shows SSH port"
      echo "    ps aux | grep qemu-system | grep hostfwd  # Shows all port forwards"
      echo ""
      echo "  Configured services (actual ports may vary):"
      echo "  - SSH access (use 'vagrant ssh')"
      echo "  - Prometheus server (port 9090)"
      echo "  - Tracee HTTP (/metrics, /healthz, /debug/pprof - port 3366)"
      echo "  - Grafana dashboard (port 3000)"
      echo "  - MkDocs documentation (port 8000)"
      if [ "#{vm_type}" = "dev" ]; then
        echo "  - MicroK8s dashboard (port 10443 - dev only)"
      fi
      echo ""
      echo "💡 Development workflow:"
      echo "  - Edit files on host (changes appear instantly in VM)"
      echo "  - Build/test in VM (results visible on host)"
      echo "  - SSH via vagrant ssh"
      echo ""
      echo "📁 Shared folder setup:"
      if [ "#{host_os}" = "Darwin" ]; then
        echo "  - macOS: 9p + bindfs for proper ownership mapping (very slow)"
      else
        echo "  - Linux: Direct 9p mount with UID/GID mapping"
      fi
      echo ""
      echo "✅ VM is ready for development!"
    SHELL
  end
end
