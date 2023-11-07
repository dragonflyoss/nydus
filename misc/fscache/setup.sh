#!/bin/bash

# This script should be executed in root mode!

apt update
apt install -y cachefilesd
apt list --installed | grep cachefilesd
chmod a+w /etc/default/cachefilesd
sed -i 's/#RUN=yes/RUN=yes/' /etc/default/cachefilesd
cat /etc/default/cachefilesd
/sbin/modprobe -qab cachefiles
/sbin/cachefilesd -f /etc/cachefilesd.conf
systemctl status cachefilesd
[ -c /dev/cachefiles ] && echo "cachefilesd is successfully enabled"
pid=$(lsof /dev/cachefiles | awk '{if (NR>1) {print $2}}')
kill -9 $pid
echo "/dev/cachefiles is available now"
