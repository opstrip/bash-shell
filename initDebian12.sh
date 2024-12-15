#!/bin/bash
###################################################################
# Description: Initialize Debian12 (buster)
# Arch: Debian GNU/Linux 12 (buster)
# Author: Jeff
# Mail: shiyao.zh@gmail.com
# Last Update: 2024.12.11
# Version: 1.0.1
###################################################################
# Usage: sh initDebian12.sh [HOSTNAME]
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
#source /etc/profile

# 以 root 用户运行该脚本
[ $(id -u) -gt 0 ] && echo -e "\E[31;49m""\033[5mPlease use root to run the script! \033[0m" && exit 1

# 禁止重置云主机名并修改
[ -f /etc/cloud/cloud.cfg ] && sed -i 's/^ - set_hostname/# - set_hostname/' /etc/cloud/cloud.cfg
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
# 设置24小时制
#alias date='date "+%a %b %d %H:%M:%S %Z %Y" '

# 禁用/关闭不常用服务
# systemctl disable firewalld && systemctl stop firewalld
# systemctl disable postfix && systemctl stop postfix
systemctl list-unit-files | grep ufw && systemctl disable --now ufw

# 关闭selinux
[ -f /etc/sysconfig/selinux ] && sed -i "s#SELINUX=enforcing#SELINUX=disabled#g" /etc/sysconfig/selinux
# setenforce 0

# 禁止ctrl-alt-del重启
[ -L /usr/lib/systemd/system/ctrl-alt-del.target ] || rm -rf /usr/lib/systemd/system/ctrl-alt-del.target
[ -L /lib/systemd/system/ctrl-alt-del.target ] || rm -rf /lib/systemd/system/ctrl-alt-del.target

# 优化history配置
chk_his=$(cat /etc/profile | grep HISTTIMEFORMAT | wc -l)
if [ $chk_his -eq 0 ];then
cat >> /etc/profile <<'EOF'
#设置history格式
export HISTTIMEFORMAT="[%Y-%m-%d %H:%M:%S] [`whoami`] [`who am i|awk '{print $NF}'|sed -r 's#[()]##g'`]: "
#记录shell执行的每一条命令
export PROMPT_COMMAND='\
if [ -z "$OLD_PWD" ];then
    export OLD_PWD=$PWD;
fi;
if [ ! -z "$LAST_CMD" ] && [ "$(history 1)" != "$LAST_CMD" ]; then
    logger -t `whoami`_shell_dir "[$OLD_PWD]$(history 1)";
fi;
export LAST_CMD="$(history 1)";
export OLD_PWD=$PWD;'
EOF
source /etc/profile

# 配置 sshd.service 服务
sed -i -e 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' -e 's/^#ClientAliveCountMax 3/ClientAliveCountMax 5/' -e 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
cat > /root/.ssh/config << EOF
Port 22
GSSAPIAuthentication no
StrictHostKeyChecking no
EOF
chmod 0600 /root/.ssh/config
systemctl restart sshd.service

# 初始化跳板机用户、rlk发布用户，添加root发布权限
cat >> /root/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDkwgd9TCY39oW9f/QqHzZzNvPySv4VUmTY0SimPf7UhI6LdUnpm54Mb4VWsDEtwyzJgF00nS9SjE/49g/uk/pjzUsVLe93r3ZFPfHCSt3wJ9Es0roRJ0w/1e9V9zSurL5txw7yfNVyx7j+nv/TrbESKG41IgjDHb0CWxpRNBmZiFuIX9DX+TdcALqqtjYxd7A6TgjahrlV/b8ZedPkE6qSTeUhginYt7he+aAcxUO8pc/SA3ogYn3qEfdChnvVqZONcd4RXR7lWkJler1MWB3UL+NmLNsY3Rf1xF/av0z4Nhadx22g/5s7mr3F9gatNw55/9+ez5wEBAnwI49zeXt9 root@jps-user
EOF
# 配置跳板机用户super
useradd super && su - super -c "ssh-keygen -t rsa -f /home/super/.ssh/id_rsa -C \"JMS User\" -N ''"
cat > /home/super/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFrbudxeAzUqicw1jszM/agr0ptcyy6IBY9ADUfQvv5a2YmDMg2b6gMWdsSxED7XzGWwzqvoecHLd21jAWvZ5gOjOLPjFQ4kTuKmZ5ir1ZmN172n+GWd2/qxe40xrISwEHtZ6KYK/GzjE5t5KJZNfzppwYqSX8CnmaILu92h8je48miPVpgh+oQ7PAs6D75CMWMcBgXWvhLKRc7jRCma4uKsb2LB7YqHhFobLG8DHjaQKemaVU8R+H3m9O6YSncfGgibYplCrbMvzevrzVZ3gz3MgoLjmOyicwcy1llNtcy+kauwYswl9Cs0M26xtiayqAg2ztb3u4v3+FLRtjnmGN super@jps-user
EOF
chown super:super /home/super/.ssh/authorized_keys && chmod 0600 /home/super/.ssh/authorized_keys && rm -f /home/super/.ssh/id_rsa*
echo "super ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# 配置程序用户rlk
if id -u rlk >/dev/null 2>&1; then
    echo "user rlk exists"
else
    useradd rlk && su - rlk -c "ssh-keygen -t rsa -f /home/rlk/.ssh/id_rsa -C \"JMS Super User\" -N ''"
fi
echo "rlk ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/rlk-users && chmod 400 /etc/sudoers.d/rlk-users
cat >> /home/rlk/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiFXmbb+ZPLW6qtLaGrKMusFkWwuu8n8+TPT5Ok03oMQLQXng9cHvyZZRthUdKZ2wimnnZodoZirU1t3Q3MHRoJMXAdlawuDxy+Mo7lOU4DLK+ohvboptvPJU9t36sXiwKioScEQqAU3ZkPnNfAmhaH4L8+vxgWPHfXs1uUmJyYShtdHJvRs/FFLVt9BjL+J1jBb+tPXgFzSFfRG4VoLdeqpL7aS3fZSo0mDS5EXbGpU6Q9MZ1DzUGwzSUBTZTijCF53XFwfJ+r/LeFNlOfh/k2eA/fMJNUaIJA3Gl9a0r9lXVGU99PaGVMkprIHgOlpGAUWsWUXy6/scuqNYCghoJ rlk@jps-user
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDM1cBnbGsTmqwiXVdZmqZRd3iZbD67bNycC0sCjWLLcMmed/359ri3EcBQ22rE7n2lnihWPKX6V/25kukSLpNW3AZIRunStrHhGX85xnQZxjZHg9Y9aIr6WPjr5VYyR2ts7nYQ/ouaNF4neaO7/j401lwKp8u2JEolu+92xwGqM9NE6nMXjItTq3uKJynjvGIKnXFtA5Lo2n5v2T50jghHEMmdJ7G9V6NGj8vJ1sFGoBDz0coBBrNADMw9ek6Z2k7qSSbP2a+CtDYjkyJN23wV7mrTvdQLF93l090ESZYpAomai3vNTfxrPKepQw00vtVo2WOF+bxYnIU6LKNeIUa1 gitlab-runner
EOF
chown rlk:rlk /home/rlk/.ssh/authorized_keys && chmod 0600 /home/rlk/.ssh/authorized_keys && rm -f /home/rlk/.ssh/id_rsa*

# 设置 10m 超时自动登出
echo export TMOUT=600 >> /etc/profile
echo set autologout=600 >> /etc/csh.cshrc

# 系统呢ulimit优化配置
cat >> /etc/security/limits.conf << EOF
root soft nofile 1024000
root hard nofile 1024000
root soft nproc 655360
root hard nproc 655360
root soft stack 983040
root hard stack 983040
root soft core unlimited
root hard core unlimited
* soft nofile 1024000
* hard nofile 1024000
* soft nproc 655360
* hard nproc 655360
* soft stack 983040
* hard stack 983040
* soft core unlimited
* hard core unlimited
EOF
ulimit -Sn ; ulimit -Hn

# 系统内核优化配置
cat >> /etc/sysctl.conf << EOF
# Any questions, please see https://songxwn.com/Linux-kernel-optimize/
# or contact Jeff <shiyao.zh@gmail.com>

fs.file-max = 9223372036854775807
fs.nr_open = 1073741816
kernel.msgmnb = 65536
kernel.msgmax = 65536
vm.max_map_count=655360
net.core.netdev_max_backlog = 25000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_rmem=16384 26214400 26214400
net.ipv4.tcp_wmem=32768 26214400 26214400
net.ipv4.tcp_window_scaling=1
net.core.somaxconn=65535
net.core.rmem_default=26214400
net.core.wmem_default=26214400 
net.core.rmem_max=26214400  
net.core.wmem_max=26214400
net.ipv4.udp_mem=374394 26214400 26214400
net.ipv4.ip_local_port_range=15000 64000
EOF
sysctl -p 2>/dev/null
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
sysctl -p 2>/dev/null

# 添加zabbix监控项
wget http://repo.zabbix.com/zabbix/7.2/release/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.2%2Bubuntu24.04_all.deb
dpkg -i zabbix-release_latest_7.2%2Bubuntu24.04_all.deb
cp /etc/zabbix/zabbix-agentd.conf{,.defaults}
cat > /etc/zabbix/zabbix_agentd.conf << EOF
PidFile=/var/run/zabbix/zabbix_agentd.pid
LogFile=/var/log/zabbix/zabbix_agentd.log
LogFileSize=0
Server=47.100.40.128,192.168.77.120
ServerActive=47.100.40.128,192.168.77.120
Hostname=undefine
Include=/etc/zabbix/zabbix_agentd.d/*.conf
EOF
sed -i "s/undefine/$HOSTNAME/" /etc/zabbix/zabbix_agentd.conf
ln -sf /lib/systemd/system/zabbix-agent.service /etc/systemd/system/zabbix-agent.service
systemctl enable zabbix-agent.service && systemctl start zabbix-agent.service

# 添加Prometheus主机监控项
[ -d /usr/local/exporter ] || mkdir -p /usr/local/exporter && cd /usr/local/exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz
tar xf node_exporter-1.8.2.linux-amd64.tar.gz && ln -sf node_exporter{-1.8.2.linux-amd64,} && chown -R nobody:nobody /usr/local/exporter/node_exporter-1.8.2.linux-amd64
cat > node-exporter.service << 'EOF'
[Unit]
Description=node_exporter
Documentation=https://prometheus.io/
After=network.target

[Service]
Type=simple
#CapabilityBoundingSet=CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_BIND_SERVICE
User=nobody
Group=nogroup
ExecStart=/usr/local/exporter/node_exporter/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
cp -f node-exporter.service /lib/systemd/systemd/node-exporter.service
systemctl enable node-exporter.service && systemctl start node-exporter.service

# 更改软件源为阿里云
sed -i.defaults -e 's#https://ftp.debian.org#https://mirrors.aliyun.com#g' -e 's#https://security.debian.org#https://mirrors.aliyun.com#g' /etc/apt/sources.list
# 安装常用软件
apt-y upgrade; apt-get -y install net-tools git gcc rsync lrzsz inetutils-telnet wget ntp dstat mlocate bind9-utils nscd psmisc python3-dev python3-pip mtr chrony lsof
apt -y install libpcre3 libpcre3-dev libmbedtls-dev libsodium-dev cmake libc-ares2 libc-ares-dev libev-dev
# 提示
echo -e "\033[32;40mElastic Compute Service initialization completed, restart the instance to take effect.\033[0m"

# 登录界面优化
cat << EOF > /etc/profile.d/login-info.sh
#!/bin/sh
#
# @Time    : 2024-12-10
# @Author  : Jeff
# @Desc    : ssh login banner
# @Link    : https://manytools.org/hacker-tools/ascii-banner/
# @Version : 0.1.0
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
shopt -q login_shell && : || return 0
echo -e "\033[31m
888       888        d8888 8888888b.  888b    888 8888888 888b    888  .d8888b.  
888   o   888       d88888 888   Y88b 8888b   888   888   8888b   888 d88P  Y88b 
888  d8b  888      d88P888 888    888 88888b  888   888   88888b  888 888    888 
888 d888b 888     d88P 888 888   d88P 888Y88b 888   888   888Y88b 888 888        
888d88888b888    d88P  888 8888888P\"  888 Y88b888   888   888 Y88b888 888  88888 
88888P Y88888   d88P   888 888 T88b   888  Y88888   888   888  Y88888 888    888 
8888P   Y8888  d8888888888 888  T88b  888   Y8888   888   888   Y8888 Y88b  d88P 
888P     Y888 d88P     888 888   T88b 888    Y888 8888888 888    Y888  \"Y8888P88 

You have logged in to an important server and all operations will be logged.
Illegal operations will be legally investigated for liability!
Please be careful!\033[0m"
# os
upSeconds="\$(cut -d. -f1 /proc/uptime)"
secs=\$((\${upSeconds}%60))
mins=\$((\${upSeconds}/60%60))
hours=\$((\${upSeconds}/3600%24))
days=\$((\${upSeconds}/86400))
UPTIME_INFO=\$(printf "%d days, %02dh %02dm %02ds" "\$days" "\$hours" "\$mins" "\$secs")
if [ -f /etc/redhat-release ] ; then
    PRETTY_NAME=\$(< /etc/redhat-release)
elif [ -f /etc/debian_version ]; then
   DIST_VER=\$(</etc/debian_version)
   PRETTY_NAME="\$(grep PRETTY_NAME /etc/os-release | sed -e 's/PRETTY_NAME=//g' -e  's/"//g') (\$DIST_VER)"
else
    PRETTY_NAME=\$(cat /etc/*-release | grep "PRETTY_NAME" | sed -e 's/PRETTY_NAME=//g' -e 's/"//g')
fi
if [[ -d "/system/app/" && -d "/system/priv-app" ]]; then
    model="\$(getprop ro.product.brand) \$(getprop ro.product.model)"
elif [[ -f /sys/devices/virtual/dmi/id/product_name ||
        -f /sys/devices/virtual/dmi/id/product_version ]]; then
    model="\$(< /sys/devices/virtual/dmi/id/product_name)"
    model+=" \$(< /sys/devices/virtual/dmi/id/product_version)"
elif [[ -f /sys/firmware/devicetree/base/model ]]; then
    model="\$(< /sys/firmware/devicetree/base/model)"
elif [[ -f /tmp/sysinfo/model ]]; then
    model="\$(< /tmp/sysinfo/model)"
fi
MODEL_INFO=\${model}
KERNEL=\$(uname -srmo)
USER_NUM=\$(who -u | wc -l)
RUNNING=\$(ps ax | wc -l | tr -d " ")
# disk
totaldisk=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | tail -1)
disktotal=\$(awk '{print \$2}' <<< "\${totaldisk}")
diskused=\$(awk '{print \$3}' <<< "\${totaldisk}")
diskusedper=\$(awk '{print \$5}' <<< "\${totaldisk}")
DISK_INFO="\033[0;33m\${diskused}\033[0m of \033[1;34m\${disktotal}\033[0m disk space used (\033[0;33m\${diskusedper}\033[0m)"
# cpu
cpu=\$(awk -F':' '/^model name/ {print \$2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//')
cpun=\$(grep -c '^processor' /proc/cpuinfo)
cpuc=\$(grep '^cpu cores' /proc/cpuinfo | tail -1 | awk '{print \$4}')
cpup=\$(grep '^physical id' /proc/cpuinfo | wc -l)
CPU_INFO="\${cpu} \${cpup}P \${cpuc}C \${cpun}L"
# get the load averages
read one five fifteen rest < /proc/loadavg
LOADAVG_INFO="\033[0;33m\${one}\033[0m / \${five} / \${fifteen} with \033[1;34m\$(( cpun*cpuc ))\033[0m core(s) at \033[1;34m\$(grep '^cpu MHz' /proc/cpuinfo | tail -1 | awk '{print \$4}')\033 MHz"
# mem
MEM_INFO="\$(cat /proc/meminfo | awk '/MemTotal:/{total=\$2/1024/1024;next} /MemAvailable:/{use=total-\$2/1024/1024; printf("\033[0;33m%.2fGiB\033[0m of \033[1;34m%.2fGiB\033[0m RAM used (\033[0;33m%.2f%%\033[0m)",use,total,(use/total)*100);}')"
# network
# extranet_ip=" and \$(curl -s ip.cip.cc)"
IP_INFO="\$(ip a | grep glo | awk '{print \$2}' | head -1 | cut -f1 -d/)\${extranet_ip:-}"
# Container info
CONTAINER_INFO="\$(sudo /usr/bin/crictl ps -a -o yaml 2> /dev/null | awk '/^  state: /{gsub("CONTAINER_", "", \$NF) ++S[\$NF]}END{for(m in S) printf "%s%s:%s ",substr(m,1,1),tolower(substr(m,2)),S[m]}')Images:\$(sudo /usr/bin/crictl images -q 2> /dev/null | wc -l)"
# info
echo -e "
 Information as of: \033[1;34m\$(date +"%Y-%m-%d %T")\033[0m
 
 \033[0;1;31mProduct\033[0m............: \${MODEL_INFO}
 \033[0;1;31mOS\033[0m.................: \${PRETTY_NAME}
 \033[0;1;31mKernel\033[0m.............: \${KERNEL}
 \033[0;1;31mCPU\033[0m................: \${CPU_INFO}
 \033[0;1;31mHostname\033[0m...........: \033[1;34m\$(hostname)\033[0m
 \033[0;1;31mIP Addresses\033[0m.......: \033[1;34m\${IP_INFO}\033[0m
 \033[0;1;31mUptime\033[0m.............: \033[0;33m\${UPTIME_INFO}\033[0m
 \033[0;1;31mMemory\033[0m.............: \${MEM_INFO}
 \033[0;1;31mLoad Averages\033[0m......: \${LOADAVG_INFO}
 \033[0;1;31mDisk Usage\033[0m.........: \${DISK_INFO} 
 \033[0;1;31mUsers online\033[0m.......: \033[1;34m\${USER_NUM}\033[0m
 \033[0;1;31mRunning Processes\033[0m..: \033[1;34m\${RUNNING}\033[0m
 \033[0;1;31mContainer Info\033[0m.....: \${CONTAINER_INFO}
"
EOF

exit 0
