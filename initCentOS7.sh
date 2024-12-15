#!/bin/bash
###################################################################
# Description: CentOS7 initCentOS7
# Arch: CentOS 7/RHEL
# Author: Jeff
# Mail: shiyao.zh@gmail.com
# Last Update: 2024.12.13
# Version: 1.5.4
###################################################################
# Usage: sh initCentOS7.sh [HOSTNAME]
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
#source /etc/profile

# 以 root 用户运行该脚本
[ $(id -u) -gt 0 ] && echo -e "\E[31;49m""\033[5mPlease use root to run the script!\033[0m" && exit 1

# 禁止重置云主机名并修改
[ -f /etc/cloud/cloud.cfg ] && sed -i 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
if [ x$1 != x ]; then
    HOSTNAME=$1
else
    # HOSTNAME="`hostname`"
    HOSTNAME=ip-$(echo $(ip addr | awk '/^[0-9]+: / {}; /inet.*global/ {print gensub(/(.*)\/(.*)/, "\\1", "g", $2)}') | sed 's/\./-/g')
fi
hostnamectl set-hostname $HOSTNAME

# 设置时区
timedatectl set-timezone Asia/Shanghai
# timedatectl set-timezone UTC

# 禁用/关闭不常用服务
systemctl disable firewalld && systemctl stop firewalld
systemctl disable postfix && systemctl stop postfix

# 配置 SELinux 及 sshd.service 服务
sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
setenforce 0
sed -i -e 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' -e 's/^#ClientAliveCountMax 3/ClientAliveCountMax 5/' -e 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
cat > /root/.ssh/config << EOF
Port 22
GSSAPIAuthentication no
StrictHostKeyChecking no
EOF
chmod 0600 /root/.ssh/config
systemctl restart sshd.service

# 设置 10m 超时自动登出
echo export TMOUT=600 >> /etc/profile
echo set autologout=600 >> /etc/csh.cshrc

# 系统内核之软硬件资源限制
# sed -i -e 's/^root/#root/g' -e '$a\* soft nproc 655360\n* hard nproc 655360\n* soft nofile 655360\n* hard nofile 655360\n* soft core unlimited\n* hard core unlimited' /etc/security/limits.conf
sed -i -e 's/^root/#root/g' -e '$a\* soft nofile 1024000\n* hard nofile 1024000\n* soft nproc 655360\n* hard nproc 655360\n* soft stack 983040\n* hard stack 983040\n* soft core unlimited\n* hard core unlimited' /etc/security/limits.conf
# 临时生效
ulimit -Sn && ulimit -Hn

# 配置systemctl服务参数
cat >> /etc/systemd/system.conf << EOF
DefaultLimitCORE=infinity
DefaultLimitNOFILE=1024000
DefaultLimitNPROC=1024000
EOF
cat >> /etc/systemd/user.conf << EOF
DefaultLimitCORE=infinity
DefaultLimitNOFILE=1024000
DefaultLimitNPROC=1024000
EOF
systemctl daemon-reload

# 配置系统内核参数
cat >> /etc/sysctl.conf << EOF

# Any questions, please see https://songxwn.com/Linux-kernel-optimize/
# or contact Jeff <shiyao.zh@gmail.com>

net.ipv4.ip_forward=0
kernel.shmall = 4294967296
fs.file-max = 655360
net.ipv4.tcp_fin_timeout = 3
net.ipv4.tcp_max_orphans = 655360
net.ipv4.tcp_timestamps = 0
net.nf_conntrack_max = 655360
net.netfilter.nf_conntrack_max = 655360
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.ipv4.tcp_max_syn_backlog = 204800
net.core.netdev_max_backlog = 204800
net.core.somaxconn = 2048
fs.nr_open = 655360
#net.ipv4.tcp_tw_reuse = 0
#net.ipv4.tcp_tw_recycle = 0
#net.ipv4.tcp_max_tw_buckets = 10000
vm.swappiness = 0
vm.dirty_background_ratio = 10
vm.dirty_ratio = 20
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.eth0.rp_filter = 0
EOF
sysctl -p 2>/dev/null

# 配置yum源
#rm -f /etc/yum.repos.d/*.repo
#curl -so /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
#curl -so /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo

# 初始化跳板机用户、rlk发布用户，添加root发布权限
cat >> /root/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDkwgd9TCY39oW9f/QqHzZzNvPySv4VUmTY0SimPf7UhI6LdUnpm54Mb4VWsDEtwyzJgF00nS9SjE/49g/uk/pjzUsVLe93r3ZFPfHCSt3wJ9Es0roRJ0w/1e9V9zSurL5txw7yfNVyx7j+nv/TrbESKG41IgjDHb0CWxpRNBmZiFuIX9DX+TdcALqqtjYxd7A6TgjahrlV/b8ZedPkE6qSTeUhginYt7he+aAcxUO8pc/SA3ogYn3qEfdChnvVqZONcd4RXR7lWkJler1MWB3UL+NmLNsY3Rf1xF/av0z4Nhadx22g/5s7mr3F9gatNw55/9+ez5wEBAnwI49zeXt9 root@jump-scooper
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCr7htvX8C9Nubc3xlGFtIo+48LsHbnidLwH+9HcOoPK+bbdiRnJTbQM6sKNC6kE6IfFP7RvbCIshBGKEDYSBj/1o+sO/Vu8GJXbXXh43z8snczFj49SywagrPWKCsQPqPa6bT7fmT6NCnp8hq5i81ts4admFek91kdwo5PvAQXPT6/Fs5aa5qmuBfcWvJoR1URzbjx2mZxvrNPL3IC+Bo2IEibgSsT4E9hEGxBQyAUMHgc9smYH6vYiWBlAGQwd+TGBnFFoFGrekaVuKxagQV9vUIxIqUIWq1TAj7Tym+3fSp9FWQZPjnzk/kvpUBD4qkbALfanPO1g4u38ByIWns9 root@engine-preprod
EOF
# 配置跳板机用户super
useradd super && su - super -c "ssh-keygen -f /home/super/.ssh/id_rsa -N ''"
cat > /home/super/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFrbudxeAzUqicw1jszM/agr0ptcyy6IBY9ADUfQvv5a2YmDMg2b6gMWdsSxED7XzGWwzqvoecHLd21jAWvZ5gOjOLPjFQ4kTuKmZ5ir1ZmN172n+GWd2/qxe40xrISwEHtZ6KYK/GzjE5t5KJZNfzppwYqSX8CnmaILu92h8je48miPVpgh+oQ7PAs6D75CMWMcBgXWvhLKRc7jRCma4uKsb2LB7YqHhFobLG8DHjaQKemaVU8R+H3m9O6YSncfGgibYplCrbMvzevrzVZ3gz3MgoLjmOyicwcy1llNtcy+kauwYswl9Cs0M26xtiayqAg2ztb3u4v3+FLRtjnmGN super@localhost
EOF
chown super:super /home/super/.ssh/authorized_keys && chmod 0600 /home/super/.ssh/authorized_keys && rm -f /home/super/.ssh/id_rsa*
echo "super ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# 配置程序用户rlk
if id -u rlk >/dev/null 2>&1; then
    echo "user rlk exists"
else
    useradd rlk && su - rlk -c "ssh-keygen -f /home/rlk/.ssh/id_rsa -N ''"
fi
echo "rlk ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/rlk-users && chmod 400 /etc/sudoers.d/rlk-users
cat >> /home/rlk/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiFXmbb+ZPLW6qtLaGrKMusFkWwuu8n8+TPT5Ok03oMQLQXng9cHvyZZRthUdKZ2wimnnZodoZirU1t3Q3MHRoJMXAdlawuDxy+Mo7lOU4DLK+ohvboptvPJU9t36sXiwKioScEQqAU3ZkPnNfAmhaH4L8+vxgWPHfXs1uUmJyYShtdHJvRs/FFLVt9BjL+J1jBb+tPXgFzSFfRG4VoLdeqpL7aS3fZSo0mDS5EXbGpU6Q9MZ1DzUGwzSUBTZTijCF53XFwfJ+r/LeFNlOfh/k2eA/fMJNUaIJA3Gl9a0r9lXVGU99PaGVMkprIHgOlpGAUWsWUXy6/scuqNYCghoJ rlk@jks.scooper.news
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDM1cBnbGsTmqwiXVdZmqZRd3iZbD67bNycC0sCjWLLcMmed/359ri3EcBQ22rE7n2lnihWPKX6V/25kukSLpNW3AZIRunStrHhGX85xnQZxjZHg9Y9aIr6WPjr5VYyR2ts7nYQ/ouaNF4neaO7/j401lwKp8u2JEolu+92xwGqM9NE6nMXjItTq3uKJynjvGIKnXFtA5Lo2n5v2T50jghHEMmdJ7G9V6NGj8vJ1sFGoBDz0coBBrNADMw9ek6Z2k7qSSbP2a+CtDYjkyJN23wV7mrTvdQLF93l090ESZYpAomai3vNTfxrPKepQw00vtVo2WOF+bxYnIU6LKNeIUa1 gitlab-runner@izgw8hspvpy48ywcdy8b41z super@172.20.0.183
EOF
chown rlk:rlk /home/rlk/.ssh/authorized_keys && chmod 0600 /home/rlk/.ssh/authorized_keys && rm -f /home/rlk/.ssh/id_rsa*
# 挂载阿里云NAS
#[ -d /home/rlk/efs ] || mkdir -p /home/rlk/efs && chown -R rlk.rlk /home/rlk/efs
#cat >> /etc/fstab << 'EOF'
#1107044a60d-rfg33.eu-central-1.nas.aliyuncs.com:/  /home/rlk/efs  nfs  vers=3,nolock,proto=tcp,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport    0 0
#EOF
#mount -a

# Install node_exporter
[ -d /usr/local/exporter ] || mkdir -p /usr/local/exporter 
cd /usr/local/exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz
# wget https://sh.opstrip.com/Packages/node_exporter-1.8.2.linux-amd64.tar.gz
tar xf node_exporter-1.8.2.linux-amd64.tar.gz && ln -sf node_exporter{-1.8.2.linux-amd64,} && chown -R nobody:nobody /usr/local/exporter/node_exporter-1.8.2.linux-amd64
cat > /usr/lib/systemd/system/node-exporter.service << 'EOF'
[Unit]
Description=node_exporter
Documentation=https://prometheus.io/
After=network.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecStart=/usr/local/exporter/node_exporter/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable node-exporter.service && systemctl start node-exporter.service

# Tracing: Jaeger Agent
# cd /usr/local/src && wget https://sh.opstrip.com/Packages/jaeger-1.62.0-linux-amd64.tar.gz
# wget https://github.com/jaegertracing/jaeger/releases/download/v1.62.0/jaeger-1.62.0-linux-amd64.tar.gz
# tar xf jaeger-1.62.0-linux-amd64.tar.gz -C /usr/local/jaeger && chown -R nobody:nobody /usr/local/jaeger
# cat > /usr/lib/systemd/system/jaeger-agent.service << 'EOF'
# [Unit]
# Description=jaeger-agent
# Documentation=https://help.aliyun.com/document_detail/266007.html
# After=network.target

# [Service]
# Type=simple
# User=nobody
# Group=nobody
# ExecStart=/usr/local/jaeger/jaeger-agent \
#           --reporter.grpc.host-port=tracing-analysis-dc-frankfurt-internal.aliyuncs.com:1883 \
#           --agent.tags=Authentication=fl8fslytgq@d04e0a7d1ebcdcc_fl8fslytgq@53df7ad2afe8301
# Restart=always

# [Install]
# WantedBy=multi-user.target
# EOF
# systemctl start jaeger-agent.service && systemctl enable jaeger-agent.service

# 安装配置 SLS
# wget http://logtail-release-eu-central-1.oss-eu-central-1.aliyuncs.com/linux64/logtail.sh -O logtail.sh; chmod 755 logtail.sh; ./logtail.sh install eu-central-1
# echo $HOSTNAME > /etc/ilogtail/user_defined_id && /etc/init.d/ilogtaild force-stop && /etc/init.d/ilogtaild start

# 安装配置 supervisor 守护软件
# yum -y install supervisor && mkdir -p /etc/supervisor/conf.d && sed -i -e 's|minfds=1024|minfds=640000|' -e 's|files = supervisord.d/\*.ini|files = /etc/supervisor/conf.d/*.conf|' /etc/supervisord.conf

# 安装常用软件
yum -y upgrade; yum -y install net-tools git gcc rsync lrzsz telnet wget ntp dstat mlocate bind-utils nscd psmisc python-devel python-pip mtr chrony lsof

# 提示
echo -e "\033[32;40mElastic Compute Service initialization completed, restart the instance to take effect.\033[0m"

exit 0
