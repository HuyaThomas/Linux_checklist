#!/bin/bash

DATE=$(date +%Y_%m_%d)
OUTPUT="$DATE.txt"
TOTAL_STEPS=13  # 总共的检查步骤数量
CURRENT_STEP=0  # 当前完成的步骤数

# 重定向标准输出和标准错误输出到文件（不包括进度条的输出）
exec 3>&1 1>>"$OUTPUT" 2>&1

# 显示进度条函数
show_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    PERCENT=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    echo -ne "检查进度: [" >&3
    for ((i=0; i<$PERCENT; i+=2)); do echo -ne "#" >&3; done
    for ((i=$PERCENT; i<100; i+=2)); do echo -ne " " >&3; done
    echo -ne "] $PERCENT% ($CURRENT_STEP/$TOTAL_STEPS)\r" >&3
}

echo "开始检查，耐心等待....." >&3
echo "当前时间：$(date)" >&3
echo >&3

# 封装函数
check_users() {
    echo "检查是否存在可疑账号"
    echo "当前用户：$(whoami)"
    echo "特权用户(UID为0的)："
    awk -F: '$3==0{print $1}' /etc/passwd
    echo "可以远程登录的用户："
    awk '/\$1|\$6/{print $1}' /etc/shadow
    echo "存在sudo权限的用户："
    grep -v "^#\|^$" /etc/sudoers | grep "ALL=(ALL)"
    echo
    show_progress
}

check_logs() {
    echo "检查账号登陆日志"
    lastlog
    echo
    show_progress
}

check_history() {
    echo "检查History历史操作命令"
    export HISTTIMEFORMAT='%F %T ' && set -o history && history
    echo
    show_progress
}

check_connections() {
    echo "检查端口连接"
    netstat -antlp
    echo
	echo "筛选公网地址以及出现的次数"
    netstat -antpl | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | grep -v -E "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))" | uniq -c
    echo
    show_progress
}

check_services() {
    echo "检查运行服务"
    ps aux
    echo
    show_progress
}

check_cron() {
    echo "检查定时任务"
    crontab -l
    echo
    show_progress
}

check_ssh_keys() {
    echo "检查SSH Key"
    SSHKEY="${HOME}/.ssh/authorized_keys"
    if [ -e "${SSHKEY}" ]; then
        cat "${SSHKEY}"
    else
        echo "SSH key文件不存在"
    fi
    echo
    show_progress
}

check_startup() {
    echo "检查开机启动项和启动配置文件"
    systemctl list-unit-files | grep enabled
    more /etc/rc.local /etc/rc3.d
    echo
    show_progress
}

check_kernel_modules() {
    echo "检查系统内核引导模块"
    stat /lib/modules
    echo
    show_progress
}

check_logins() {
    echo "检查所有登陆信息"
    who /var/log/wtmp
    echo "检查登陆失败的信息"
    who /var/log/btmp
    echo "检查所有登录成功的日期"
    ls -l /var/log/secure*
    grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
    echo "检查登录成功的IP"
    grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
    echo
    show_progress
}

check_accounts() {
    echo "检查增删账号"
    grep "useradd" /var/log/secure
    grep "userdel" /var/log/secure
    echo
    show_progress
}

check_sensitive_directories() {
    echo "检查敏感目录"
    ls -l /var/spool/cron/*
    ls -l /etc/cron.d/*
    ls -l /etc/cron.daily/*
    ls -l /etc/rc.d/init.d/
    ls -l /etc/cron.hourly/*
    ls -l /var/spool/anacron/*
    echo
    show_progress
}

# 调用函数
check_users
check_logs
check_history
check_connections
check_services
check_cron
check_ssh_keys
check_startup
check_kernel_modules
check_logins
check_accounts
check_sensitive_directories

echo -e "\n检查完毕" >&3

#检查原生RPM包是否被篡改
##rpm -Va
#检查守护进程是否由systemd管理
##systemctl list-units --type=service | grep