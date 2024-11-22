#!/bin/bash

set -euxo pipefail
script_dir=$(dirname "${BASH_SOURCE[0]}")
script_dir=$(cd "${script_dir}" &>/dev/null && pwd -P)

modprobe tun

if [ ! -e /dev/net ]; then
  mkdir /dev/net
fi
if [ ! -e /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
  chmod 0666 /dev/net/tun
fi

if [ $(ip tuntap list | grep "${WSN_DEVICE}" | wc -l) -gt 0 ]; then
  ip tuntap del dev "${WSN_DEVICE}" mode tap
fi
if [ -e "/dev/net/${WSN_DEVICE}" ]; then
  rm "/dev/net/${WSN_DEVICE}"
fi
ip tuntap add dev "${WSN_DEVICE}" mode tap
ip   addr add dev "${WSN_DEVICE}" 192.168.42.1/24 broadcast 192.168.42.255
ip   link set dev "${WSN_DEVICE}" mtu 1404
ip   link set dev "${WSN_DEVICE}" up

exec "${script_dir}/wsn-client"
