packer {
  required_plugins {
    amazon = {
      version = ">= 1.1.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

source "amazon-ebs" "ubuntu" {
  ami_name      = "ubuntu-tracee-testing"
  instance_type = "t2.micro"
  region        = "us-east-1"
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/*ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

build {
  name    = "ubuntu-tracee-testing"
  sources = [
    "source.amazon-ebs.ubuntu"
  ]
  provisioner "shell" {
	inline = [
		"sudo apt update",
    "sudo apt install -y git make wget libelf-dev elfutils clang golang"
  ]
  }
}