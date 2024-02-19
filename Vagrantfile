# -*- mode: ruby -*-
# vi: set ft=ruby :

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

vm_name = "tracee-#{arch}-vm"

Vagrant.configure("2") do |config|
  config.vm.network "forwarded_port", guest: 9090, host: 9090
  config.vm.network "forwarded_port", guest: 3366, host: 3366
  config.vm.network "forwarded_port", guest: 3000, host: 3000
  case arch
  when "amd64"
    # config.vm.box = "ubuntu/focal64"     # Ubuntu 20.04 Focal Fossa (non CO-RE)
    # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
    # config.vm.box = "ubuntu/impish64"    # Ubuntu 21.10 Impish Indri (CO-RE)
    config.vm.box = "ubuntu/jammy64"       # Ubuntu 22.04 Jammy Jellyfish (CO-RE)
  when "arm64"
    config.vm.box = "bento/ubuntu-22.04-arm64"
  end

  case host_os
  when "Linux"
    config.vm.provider "virtualbox" do |vb|
      vb.name = vm_name
      vb.cpus = "8"
      vb.memory = "4096"
      vb.gui = false
    end
  when "Darwin"
    config.vm.provider "parallels" do |prl|
      prl.name = vm_name
    end
  end

  config.ssh.extra_args = ["-t", "cd /vagrant; bash --login"]

  # Forward MkDocs dev server to preview documentation on the host at http://localhost:8000/tracee
  config.vm.network :forwarded_port, guest: 8000, host: 8000

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
  config.vm.network :forwarded_port, guest: 10443, host: 10443

  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    VAGRANT_HOME="/home/vagrant"
    GO_VERSION="1.21.6"
    OPA_VERSION="v0.61.0"

    # silence 'dpkg-preconfigure: unable to re-open stdin: No such file or directory'
    export DEBIAN_FRONTEND=noninteractive

    apt-get update

    #
    # build environment for tracee
    #

    apt-get install --yes bsdutils
    apt-get install --yes build-essential
    apt-get install --yes pkgconf

    apt-get install --yes llvm-12 clang-12
    apt-get install --yes clang-format-12
    for tool in "clang" "llc" "llvm-strip"
    do
      path=$(which $tool-12)
      ln -s "$path" "${path%-*}"
    done

    apt-get install --yes zlib1g-dev libelf-dev
    apt-get install --yes protobuf-compiler
    apt-get install --yes linux-tools-"$(uname -r)" ||
      apt-get install --yes linux-tools-generic

    # golang
    wget --quiet https://golang.org/dl/go$GO_VERSION.linux-#{arch}.tar.gz
    tar -C /usr/local -xzf go$GO_VERSION.linux-#{arch}.tar.gz
    GOBIN_PATH=/usr/local/go/bin
    echo "export PATH=$PATH:$GOBIN_PATH" >> $VAGRANT_HOME/.profile
    # integration tests run as root, so go needs to be in root's path as well
    echo "export PATH=$PATH:$GOBIN_PATH" >> $HOME/.bashrc
    # sudo needs to be able to find go as well
    echo "Defaults secure_path=\"$PATH:$GOBIN_PATH\"" >> /etc/sudoers.d/vagrant

    #
    # microk8s
    #

    snap install microk8s --classic
    microk8s status --wait-ready
    usermod -a -G microk8s vagrant
    microk8s enable hostpath-storage dns dashboard

    mkdir -p $VAGRANT_HOME/.kube/
    microk8s kubectl config view --raw > $VAGRANT_HOME/.kube/config
    chmod 600 $VAGRANT_HOME/.kube/config
    chown vagrant:vagrant $VAGRANT_HOME/.kube/config

    #
    # kubectl
    #

    apt-get install --yes apt-transport-https ca-certificates curl
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
    apt-get update
    apt-get install --yes kubectl
    echo 'source <(kubectl completion bash)' >> $VAGRANT_HOME/.profile

    #
    # helm
    #

    snap install helm --classic
    echo 'source <(helm completion bash)' >> $VAGRANT_HOME/.profile

    #
    # docker
    #

    apt-get install --yes docker.io
    usermod -aG docker vagrant

    #
    # opa
    #

    curl -L -o /usr/bin/opa https://github.com/open-policy-agent/opa/releases/download/$OPA_VERSION/opa_linux_#{arch}
    chmod 755 /usr/bin/opa
  SHELL
end
