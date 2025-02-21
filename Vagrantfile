# -*- mode: ruby -*-
# vi: set ft=ruby :

require 'etc'

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

vm_proc = ENV["VM_PROC"]
if vm_proc.nil? || vm_proc.empty?
  vm_proc = Etc.nprocessors / 2
end

# in GB
vm_mem = ENV["VM_MEM"]
if vm_mem.nil? || vm_mem.empty?
  vm_mem = "8"
end

vm_user = "vagrant"
vm_synced_folder = "/#{vm_user}"

provider_settings = lambda do |prov, name|
  if name == "virtualbox" || name == "parallels"
    prov.name = vm_name
    prov.cpus = vm_proc
    prov.memory = vm_mem.to_i * 1024
  end
  if name == "virtualbox"
    prov.gui = false
  end
  if name == "parallels"
    prov.update_guest_tools = true
  end
end

Vagrant.configure("2") do |config|
  config.ssh.extra_args = ["-t", "cd #{vm_synced_folder}; bash --login"]

  # set the synced folder type based on the host OS and architecture
  if host_os == "Linux" || (host_os == "Darwin" && arch == "amd64")
    config.vm.synced_folder ".", "#{vm_synced_folder}", type: "virtualbox", auto_mount: false
  elsif host_os == "Darwin" && arch == "arm64"
    config.vm.synced_folder ".", "#{vm_synced_folder}", type: "parallels"
  end

  # define the machine with the dynamically set vm_name
  config.vm.define vm_name do |vm_config|
    # virtualbox, parallels, vmware_desktop, qemu, libvirt
    vm_config.vm.box = "bento/ubuntu-22.04"

    case host_os
    when "Linux"
      vm_config.vm.provider "virtualbox" do |vb|
        provider_settings.call(vb, "virtualbox")
      end
    when "Darwin"
      case arch
      when "amd64"
        vm_config.vm.provider "virtualbox" do |vb|
          provider_settings.call(vb, "virtualbox")
        end
      end
      when "arm64"
        vm_config.vm.provider "parallels" do |prl|
          provider_settings.call(prl, "parallels")
        end
    end

    # network settings
    vm_config.vm.hostname = vm_name

    vm_config.vm.network "forwarded_port", guest: 9090, host: 9090, auto_correct: true
    vm_config.vm.network "forwarded_port", guest: 3366, host: 3366, auto_correct: true
    vm_config.vm.network "forwarded_port", guest: 3000, host: 3000, auto_correct: true
    # forward MkDocs dev server to preview documentation on the host at http://localhost:8000/tracee
    vm_config.vm.network :forwarded_port, guest: 8000, host: 8000, auto_correct: true

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
      vm_config.vm.network :forwarded_port, guest: 10443, host: 10443, auto_correct: true
    end

    vm_config.vm.provision "shell", privileged: true, inline: <<-SHELL
      set -e

      ARCH="#{arch}"
      USER="#{vm_user}"
      HOME="/home/#{vm_user}"
      LLVM_VERSION="14"
      GO_VERSION="1.24.0"
      KUBECTL_VERSION="v1.29"
      VM_TYPE="#{vm_type}"

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      echo ">>> Updating system packages"
      apt-get update
      apt-get --yes upgrade

      #
      # build environment for tracee
      #

      echo ">>> Installing build environment for tracee"
      apt-get install --yes bsdutils
      apt-get install --yes build-essential
      apt-get install --yes pkgconf

      apt-get install --yes llvm-${LLVM_VERSION} clang-${LLVM_VERSION}
      for tool in "clang" "llc" "llvm-strip"
      do
        path=$(which ${tool}-${LLVM_VERSION})
        ln -s -f "$path" "${path%-*}"
      done

      rm -f /usr/bin/clang-format-12
      curl -L -o /tmp/clang-format-12 https://github.com/muttleyxd/clang-tools-static-binaries/releases/download/master-f4f85437/clang-format-12.0.1_linux-${ARCH}
      sudo mv -f /tmp/clang-format-12 /usr/bin/clang-format-12
      sudo chmod 755 /usr/bin/clang-format-12

      apt-get install --yes zlib1g-dev libelf-dev libzstd-dev
      apt-get install --yes protobuf-compiler

      # golang
      cd /tmp
      wget --quiet https://golang.org/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz
      tar -C /usr/local -xzf go${GO_VERSION}.linux-${ARCH}.tar.gz
      GOBIN_PATH=/usr/local/go/bin
      echo "export PATH=${PATH}:${GOBIN_PATH}" >> ${HOME}/.profile
      # integration tests run as root, so go needs to be in root's path as well
      echo "export PATH=${PATH}:${GOBIN_PATH}" >> $HOME/.bashrc
      # sudo needs to be able to find go as well
      echo "Defaults secure_path=\"${PATH}:${GOBIN_PATH}\"" >> /etc/sudoers.d/${USER}
      rm -f go${GO_VERSION}.linux-${ARCH}.tar.gz
      cd -

      # other tools
      apt-get install --yes python3 pip jq
      pip install docker boto3 psutil jmespath

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

    SHELL

    vm_config.vm.provision "shell", privileged: true, reboot: true, inline: <<-SHELL
      set -e

      KERNEL_VERSION="6.2.0-1018-aws"
      USER="#{vm_user}"

      # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
      export DEBIAN_FRONTEND=noninteractive

      echo ">>> Installing kernel ${KERNEL_VERSION}"
      apt-get install --yes \
        dkms \
        linux-image-${KERNEL_VERSION} \
        linux-headers-${KERNEL_VERSION} \
        linux-modules-${KERNEL_VERSION} \
        linux-tools-${KERNEL_VERSION}
    SHELL

    share_provisioning = lambda do |vm_config, name|
      if name == "virtualbox"
        vbox_version = `VBoxManage --version`.strip.match(/^(\d+\.\d+\.\d+)/)[1]

        # this provision stage must always run to ensure the shared folder is mounted
        # when host changes the VirtualBox Guest Additions version.
        vm_config.vm.provision "shell", run: "always", privileged: true, inline: <<-SHELL
          set +e

          VBOX_VERSION="#{vbox_version}"
          SYNCED_FOLDER="#{vm_synced_folder}"
          USER="#{vm_user}"

          echo ">>> Installing VirtualBox Guest Additions ${VBOX_VERSION}"
          cd /tmp
          wget --quiet https://download.virtualbox.org/virtualbox/${VBOX_VERSION}/VBoxGuestAdditions_${VBOX_VERSION}.iso
          mkdir -p /mnt/media
          mount -o loop,ro VBoxGuestAdditions_${VBOX_VERSION}.iso /mnt/media
          /mnt/media/VBoxLinuxAdditions.run --nox11
          umount /mnt/media
          rm -f VBoxGuestAdditions_${VBOX_VERSION}.iso
          cd -
          /sbin/rcvboxadd quicksetup all

          echo ">>> Mounting shared folder ${SYNCED_FOLDER}"
          mkdir -p ${SYNCED_FOLDER}
          mount -t vboxsf -o uid=1000,gid=1000,_netdev ${USER} ${SYNCED_FOLDER}
        SHELL
      elsif name == "parallels"
        # nothing to do here, shared folders are mounted automatically
      end
    end

    if host_os == "Linux" || (host_os == "Darwin" && arch == "amd64")
      share_provisioning.call(vm_config, "virtualbox")
    elsif host_os == "Darwin" && arch == "arm64"
      share_provisioning.call(vm_config, "parallels")
    end
  end
end
