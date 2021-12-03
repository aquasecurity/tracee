# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install --yes build-essential pkgconf libelf-dev llvm-12 clang-12

    for tool in "clang" "llc" "llvm-strip"
    do
      path=$(which $tool-12)
      sudo ln -s $path ${path%-*}
    done

    apt-get install --yes docker.io
    usermod -aG docker vagrant

    wget --quiet https://golang.org/dl/go1.16.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.16.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile
  SHELL
end

