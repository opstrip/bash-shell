#!/bin/bash
###################################################################
# Description: Rocky 9/Debian 12/Ubuntu 24.04 initSystem.sh
# Arch: rocky/debian/ubuntu/centos
# Author: Jeff
# Mail: shiyao.zh@gmail.com
# Link: https://github.com/opstrip/bash-shell
# Last Update: 2024.12.14
# Version: 1.0.2
###################################################################
# Usage: sh initSystem.sh [HOSTNAME]
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin:/snap/bin
os=$(cat /etc/os-release 2>/dev/null | grep ^ID= | awk -F'[=\"]+' '{print $2}')

function HOSTNAMESET(){
    # 禁止重置云主机名并修改
    [ -f /etc/cloud/cloud.cfg ] && sed -i 's/preserve_hostname: false/preserve_hostname: true/g' /etc/cloud/cloud.cfg
    if [ x$1 != x ]; then
        HOSTNAME=$1
    else
        # HOSTNAME="`hostname`"
        [ "$os" = "ubuntu" ] && apt install -y gawk && sleep 1
        # Ubuntu未安装gawk会报“awk: line 2: function gensub never defined”错误
        HOSTNAME=ip-$(echo $(ip addr | awk '/^[0-9]+: / {}; /inet.*global/ {print gensub(/(.*)\/(.*)/, "\\1", "g", $2)}') | sed 's/\./-/g')
    fi
    hostnamectl set-hostname $HOSTNAME
}

function SELINUXSET(){    
    # Ubuntu 24.04 selinux相关配置
    # [ "$os" = "ubuntu" ] && apt install -y policycoreutils && sleep 1 && sed -i "s#SELINUX=permissive#SELINUX=disabled#g" /etc/selinux/config
    selinux_status=$(grep -c "SELINUX=disabled" /etc/sysconfig/selinux)
    echo "========================禁用SELINUX========================"
    if [ "$selinux_status" -eq 0 ];then
        sed -i "s#SELINUX=enforcing#SELINUX=disabled#g" /etc/sysconfig/selinux
        setenforce 0
        grep SELINUX=disabled /etc/sysconfig/selinux
        getenforce
    else
        echo 'SELINUX已处于关闭状态'
        grep SELINUX=disabled /etc/sysconfig/selinux
        getenforce
    fi
    echo "完成禁用SELINUX"
    echo "==========================================================="
    sleep 3
}

function FIREWALLSET(){
    echo "========================关闭ufw============================"
    echo '关闭防火墙'
    systemctl list-unit-files | grep iptables && systemctl disable --now iptables
    systemctl list-unit-files | grep firewalld && systemctl disable --now firewalld
    systemctl list-unit-files | grep ufw && systemctl disable --now ufw
    echo '验证如下'
    systemctl list-unit-files | grep -E 'iptables|firewalld|ufw'
    echo '生产环境下建议启用'
    echo "==========================================================="
    sleep 3
}

function LIMITSSET(){
    echo "======================修改文件描述符========================"
    # sed -i -e 's/^root/#root/g' -e '$a\* soft nproc 655360\n* hard nproc 655360\n* soft nofile 1024000\n* hard nofile 1024000\n* soft stack 983040\n* hard stack 983040\n* soft core unlimited\n* hard core unlimited' /etc/security/limits.conf
    if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
        echo 'debian系列系统特殊配置'
        {
            echo 'root soft nofile 1024000'
            echo 'root hard nofile 1024000'
            echo 'root soft nproc 655360'
            echo 'root hard nproc 655360'
            echo 'root soft stack 983040'
            echo 'root hard stack 983040'
            echo 'root soft core unlimited'
            echo 'root hard core unlimited'
        } >> /etc/security/limits.conf
    fi
    echo '增加系统文件描述符最大值'
    {
        echo '* soft nofile 1024000'
        echo '* hard nofile 1024000'
        echo '* soft nproc 655360'
        echo '* hard nproc 655360'
        echo '* soft stack 983040'
        echo '* hard stack 983040'
        echo '* soft core unlimited'
        echo '* hard core unlimited'
    } >> /etc/security/limits.conf
    echo '查看配置内容'
    cat /etc/security/limits.conf
    echo '设置软硬资源限制'
    ulimit -Sn ; ulimit -Hn
    echo "==========================================================="
    sleep 3
}

function SYSCTLSET(){
    echo "======================修改内核参数========================"
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
}

function YUMSET(){
    echo "======================开始修改YUM源========================"
    echo '开始修改YUM源'
    sudo sed -e 's|^mirrorlist=|#mirrorlist=|g' -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.tuna.tsinghua.edu.cn|g' -i.defaults /etc/yum.repos.d/${os}.repo
    echo '开始安装常规软件'
    # yum update -y; yum install curl git wget ntpdate lsof net-tools telnet vim lrzsz tree nmap nc sysstat epel* -y
    yum -y upgrade; yum -y install net-tools git gcc rsync vim lrzsz tree nmap nc sysstat telnet wget ntpdate dstat mlocate bind-utils nscd psmisc mtr chrony lsof supervisord epel*
    echo "==========================================================="
    sleep 3
}

function APTSET(){
    echo "======================开始修改APT源========================"
    echo '开始修改APT源'
    apt_stat=$(cat /etc/apt/sources.list | grep -v ^\# | awk -F/ '{print $3}' | grep -v ^$  | awk 'NR==1{print}')
    sudo sed -i "s/${apt_stat}/mirrors.ustc.edu.cn/g" /etc/apt/sources.list
    echo '开始安装常规软件'
    # apt update -y; apt upgrade -y; apt install vim htop net-tools lrzsz nmap telnet ntpdate sysstat curl git wget -y
    apt update -y; apt upgrade -y; apt install -y net-tools git gcc rsync gawk lrzsz inetutils-telnet wget ntp dstat mlocate bind9-utils nscd psmisc python3-dev python3-pip mtr chrony lsof supervisor epel*
    echo "==========================================================="
    sleep 3
}

function REBOOTSET(){
    echo "===================禁用ctrl+alt+del重启===================="
    [ -L /usr/lib/systemd/system/ctrl-alt-del.target ] || rm -rf /usr/lib/systemd/system/ctrl-alt-del.target
    [ -L /lib/systemd/system/ctrl-alt-del.target ] || rm -rf /lib/systemd/system/ctrl-alt-del.target
    echo "完成禁用ctrl+alt+del重启"
    echo "==========================================================="
    sleep 3
}

function HISTORYSET(){
    echo "========================history优化========================"
    chk_his=$(cat /etc/profile | grep HISTTIMEFORMAT |wc -l)
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
    else
    echo "优化项已存在。"
    fi
    echo "完成history优化" 
    echo "==========================================================="
    sleep 3
}

function MOTDSET(){
    echo "========================布告栏信息========================"
    echo "# @Link: https://manytools.org/hacker-tools/ascii-banner/"
    echo "[根据需要修改，注意网络安全]用来存放布告栏信息，一般云服务厂商的logo就在这里。"
    [ -f /etc/motd ] && cp -f /etc/motd{,.defaults}
    cat > /etc/motd << 'EOF'
  8888888b.                        888        d88P  .d8888b.                            
  888   Y88b                       888       d88P  d88P  Y88b                           
  888    888                       888      d88P   888    888                           
  888   d88P 888d888  .d88b.   .d88888     d88P    888         .d88b.  888d888  .d88b.  
  8888888P"  888P"   d88""88b d88" 888    d88P     888        d88""88b 888P"   d8P  Y8b 
  888        888     888  888 888  888   d88P      888    888 888  888 888     88888888 
  888        888     Y88..88P Y88b 888  d88P       Y88b  d88P Y88..88P 888     Y8b.     
  888        888      "Y88P"   "Y88888 d88P         "Y8888P"   "Y88P"  888      "Y8888  

                             -- Any questions, please contact Jeff<shiyao.zh@gmail.com>

EOF
    echo "已完成布告栏信息更新。"
    echo "==========================================================="
    sleep 3
}

function WARNINGSET(){
    echo "========================欢迎界面优化========================"
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
    echo "==========================================================="
    sleep 3
}

function SSHSET(){
    echo "========================root登录优化========================"
    # 配置 sshd.service 服务
    sed -i -e 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' -e 's/^#ClientAliveCountMax 3/ClientAliveCountMax 5/' -e 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    cat > /root/.ssh/config << EOF
Port 22
GSSAPIAuthentication no
StrictHostKeyChecking no
EOF
    chmod 0600 /root/.ssh/config
    systemctl restart sshd.service
    echo "==========================================================="
    sleep 3
}

function JMSSET(){
    echo "========================添加跳板机登录权限========================"
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
}

function PROMSET(){
    echo "========================添加主机监控项========================"
    # Install node_exporter
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
Group=nobody
ExecStart=/usr/local/exporter/node_exporter/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    if [ "$os" = "centos" ] || [ "$os" = "rocky" ]; then
        cp -f node-exporter.service /usr/lib/systemd/system/node-exporter.service
    elif [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
        sed -i 's#Group=nobody#Group=nogroup#g' node-exporter.service
        cp -f node-exporter.service /lib/systemd/systemd/node-exporter.service
    else
        echo "node-exporter.service服务配置失败！！"
        echo "未适配的系统版本：$os"
    fi
    systemctl enable node-exporter.service && systemctl start node-exporter.service
}

function ALLIN() {
    if [ "$os" = "centos" ] || [ "$os" = "rocky" ]; then
        HOSTNAMESET
        SELINUXSET
        SSHSET
        FIREWALLSET
        LIMITSSET
        SYSCTLSET
        YUMSET
        REBOOTSET
        HISTORYSET
        # MOTDSET
        WARNINGSET
        JMSSET
        PROMSET
    elif [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
        HOSTNAMESET
        SELINUXSET
        SSHSET
        FIREWALLSET
        LIMITSSET
        SYSCTLSET
        APTSET
        REBOOTSET
        HISTORYSET
        # MOTDSET
        WARNINGSET
        JMSSET
        PROMSET
    else
        echo "未适配的系统版本！！"
        echo "$os"
    fi
}

function MENU() {
    clear
    echo "#####################################################################"
    echo -e "#           ${RED}一键基础优化脚本${PLAIN}                         #"
    echo -e "# ${GREEN}作者${PLAIN}: Jeff                                     #"
    echo -e "# ${GREEN}网址${PLAIN}: https://opstrip.com                       #"
    echo -e "# ${GREEN}版本${PLAIN}: V1.0                                     #"
    echo -e "# ${GREEN}说明${PLAIN}: https://sh.opstrip.com/initSystem.sh     #"
    echo -e "#                                                               #"
    echo "####################################################################"
    echo " -------------"
    echo -e "  ${GREEN}1.${PLAIN}  一键优化"
    echo " -------------"
    echo -e "  ${GREEN}2.${PLAIN}  自定义优化"
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN}  退出"
    echo " -------------"

    read -p " 请选择操作[0-2]：" SETX
    case $SETX in
        0)
            exit 0
            ;;
        1)
            ALLIN
            ;;
        2)
            SETUN
            ;;
        *)
            colorEcho $RED " 请选择正确的操作！"
            exit 1
            ;;
    esac
}

function SETUN() {
    echo " -------------"
    echo -e "  ${GREEN}1.${PLAIN} 配置主机名"
    echo " -------------"
    echo -e "  ${GREEN}2.${PLAIN} 禁用SELINUX"
    echo " -------------"
    echo -e "  ${GREEN}3.${PLAIN} 关闭防火墙"
    echo " -------------"
    echo -e "  ${GREEN}4.${PLAIN} 配置文件描述符"
    echo " -------------"
    echo -e "  ${GREEN}5.${PLAIN} 优化系统内核参数"
    echo " -------------"
    echo -e "  ${GREEN}6.${PLAIN} 配置软件源"
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN} 禁用ctrl+alt+del重启"
    echo " -------------"
    echo -e "  ${GREEN}8.${PLAIN} 优化history"
    echo " -------------"
    echo -e "  ${GREEN}9.${PLAIN} 使用布告栏信息发布"
    echo " -------------"
    echo -e "  ${GREEN}10.${PLAIN} 系统欢迎界面配置"
    echo " -------------"
    echo -e "  ${GREEN}11.${PLAIN} 优化SSH服务"
    echo " -------------"
    echo -e "  ${GREEN}12.${PLAIN} 添加JumpServer信任"
    echo " -------------"
    echo -e "  ${GREEN}13.${PLAIN} 添加Prometheus主机监控项"
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN} 退出"
    echo " -------------"
    
    read -p " 请选择操作[0-2]：" OPTS
    case $OPTS in
        0)
            exit 0
            ;;
        1)
            HOSTNAMESET
            ;;
        2)
            SELINUXSET
            ;;
        3)
            FIREWALLSET
            ;;
        4)
            LIMITSSET
            ;;
        5)
            SYSCTLSET
            ;;
        6)
            if [ "$os" = "centos" ] || [ "$os" = "rocky" ]; then
                YUMSET
            elif [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
                APTSET
            else
                echo "未适配的系统版本！！"
                echo "$os"
            fi
            ;;
        7)
            REBOOTSET
            ;;
        8)
            HISTORYSET
            ;;
        9)
            MOTDSET
            ;;
        10)
            WARNINGSET
            ;;
        11)
            SSHSET
            ;;
        12)
            JMSSET
            ;;
        13)
            PROMSET
            ;;
        *)
            colorEcho $RED " 请选择正确的操作！"
            exit 1
            ;;
    esac
}


if [ $(id -u) -eq 0 ];then
    MENU
else
    echo "非root用户!请使用root用户！！！"
    exit 1
fi
