# -*- mode: ruby -*-

# Vagrant file API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

['vagrant-reload', 'vagrant-disksize'].each do |plugin|
  unless Vagrant.has_plugin?(plugin)
    raise "Vagrant plugin #{plugin} is not installed!"
  end
end

# the directory where the provisioning scripts are located
$base_dir = File.dirname(File.realdirpath(__FILE__))

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # All Vagrant configuration is done here. The most common configuration
  # options are documented and commented below. For a complete reference,
  # please see the online documentation at https://docs.vagrantup.com.
  config.vm.box = "generic/ubuntu1804"
  config.disksize.size = "45GB"

  # e.g. for wireshark forwarding
  config.ssh.forward_x11 = true
  config.ssh.forward_agent = true

  config.vm.synced_folder ".", "/vagrant/dpdk/", type: "nfs"
  config.vm.provision "shell", inline: "echo 'cd /vagrant' >> /home/vagrant/.bashrc", run: "always"

  config.vm.network "public_network", dev: "net1", type: "bridge", ip: "192.168.10.3"
  config.vm.network "public_network", dev: "net2", type: "bridge", ip: "192.168.11.3"

  config.vm.provision "shell", path: "#{$base_dir}/vm-setup.sh"
  
  # libvirt-specific configuration
  config.vm.provider "libvirt" do |v|
    # Set machine name, memory and CPU limits
    v.memory = 6144
    v.cpus = 4

  end
end
