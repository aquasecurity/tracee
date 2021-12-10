# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end

  config.vm.provision "shell", inline: <<-SHELL
    GO_VERSION="1.16"
    OPA_VERSION="v0.35.0"

    apt-get update
    apt-get install --yes build-essential pkgconf libelf-dev llvm-12 clang-12

    for tool in "clang" "llc" "llvm-strip"
    do
      path=$(which $tool-12)
      sudo ln -s $path ${path%-*}
    done

    apt-get install --yes docker.io
    usermod -aG docker vagrant

    wget --quiet https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz
    tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile

    curl -L -o /usr/bin/opa https://github.com/open-policy-agent/opa/releases/download/$OPA_VERSION/opa_linux_amd64
    chmod 755 /usr/bin/opa
  SHELL
end
