#!/bin/bash


if [ "$EUID" -ne 0 ] ;  then
	echo "Please run as root"
	echo "sudo -E ./setup.sh"
	exit -1
fi

modprobe uio_pci_generic
dpdk-devbind.py --status

mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge/
echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 512 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

dpdk-devbind.py --bind=uio_pci_generic 86:00.0
dpdk-devbind.py --status
