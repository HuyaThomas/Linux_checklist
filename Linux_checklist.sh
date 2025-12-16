#!/bin/bash

# ================= 配置与初始化 =================
export LANG=en_US.UTF-8

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 获取主机信息
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
DATE=$(date +%Y_%m_%d_%H%M)
OUTPUT="Security_Audit_${HOSTNAME}_${IP}_${DATE}.txt"

# 权限检查
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[Error] 此脚本必须以 Root 权限运行！${NC}"
   exit 1
fi

# 自动识别日志文件
if [ -f /var/log/secure ]; then
    AUTH_LOG="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
    AUTH_LOG="/var/log/auth.log"
else
    AUTH_LOG="/var/log/messages"
fi

# 定义检查列表
CHECKS=(
    "check_system_info"
    "check_resources"
    "check_network"
    "check_processes"
    "check_users_auth"
    "check_persistence"
    "check_file_integrity"
    "check_logs"
)

TOTAL_STEPS=${#CHECKS[@]}
CURRENT_STEP=0

# 重定向设置：FD3输出到终端，FD1和FD2输出到文件
exec 3>&1 1>>"$OUTPUT" 2>&1

# ================= 辅助函数 =================

show_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    PERCENT=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    BAR_LEN=20
    FILLED_LEN=$((PERCENT * BAR_LEN / 100))
    
    echo -ne "正在执行: [" >&3
    for ((i=0; i<$FILLED_LEN; i++)); do echo -ne "#" >&3; done
    for ((i=$FILLED_LEN; i<$BAR_LEN; i++)); do echo -ne " " >&3; done
    echo -ne "] $PERCENT% ($CURRENT_STEP/$TOTAL_STEPS) \r" >&3
}

print_section() {
    echo -e "\n################################################################"
    echo "### $1"
    echo "################################################################"
}

print_info() {
    echo -e "\n>>> $1"
}

# ================= 核心检查模块 =================

check_system_info() {
    print_section "1. 系统基础信息 (System Info)"
    echo "主机名    : $HOSTNAME"
    echo "IP地址    : $(hostname -I)"
    echo "内核版本  : $(uname -r)"
    echo "OS版本    : $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    echo "当前时间  : $(date)"
    show_progress
}

check_resources() {
    print_section "2. 系统资源状态 (System Resources)"
    print_info "内存使用情况 (Memory):"
    free -h
    print_info "磁盘使用情况 (Disk):"
    df -h | grep -v tmpfs
    print_info "系统负载 (Load Average):"
    uptime
    show_progress
}

check_network() {
    print_section "3. 网络安全分析 (Network Security)"
    
    print_info "网卡混杂模式检查 (Promiscuous Mode - 嗅探风险):"
    if ip link | grep -i "promisc"; then
        echo "!!! 警告: 发现网卡处于混杂模式，可能存在流量窃听 !!!"
    else
        echo "正常: 网卡未处于混杂模式。"
    fi

    print_info "DNS 设置 (/etc/resolv.conf):"
    cat /etc/resolv.conf
    
    print_info "Hosts 文件 (/etc/hosts):"
    cat /etc/hosts

    print_info "监听端口 (Listening Ports):"
    if command -v netstat >/dev/null; then
        netstat -antlp | grep LISTEN
    else
        ss -antlp | grep LISTEN
    fi

    print_info "外部连接统计 (Established Connections):"
    if command -v netstat >/dev/null; then
        netstat -antpl | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10
    else
        ss -antpl | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10
    fi
    show_progress
}

check_processes() {
    print_section "4. 进程行为分析 (Process Analysis)"
    
    print_info "内存中运行的已删除文件 (Hidden Processes - Rootkit/木马特征):"
    # 查找 exe 指向 (deleted) 的进程
    HIDDEN=$(ls -al /proc/*/exe 2>/dev/null | grep 'deleted')
    if [ -n "$HIDDEN" ]; then
        echo "!!! 发现可疑进程 (文件已删除但在运行) !!!"
        echo "$HIDDEN"
    else
        echo "未发现明显的隐藏进程。"
    fi

    print_info "占用 CPU 最高的 5 个进程:"
    ps aux --sort=-%cpu | head -6
    
    print_info "占用 内存 最高的 5 个进程:"
    ps aux --sort=-%mem | head -6
    show_progress
}

check_users_auth() {
    print_section "5. 账号与认证安全 (Account & Auth)"
    
    print_info "特权用户 (UID=0):"
    awk -F: '$3==0{print $1}' /etc/passwd
    
    print_info "影子文件可登录账号 (Remote Login Enabled):"
    awk -F: '($2!~/[!*]/){print $1}' /etc/shadow

    print_info "Sudo 权限用户:"
    grep -v "^#\|^$" /etc/sudoers | grep "ALL=(ALL)"

    print_info "SSH 公钥检查 (Authorized Keys):"
    # 遍历 /root 和 /home 下所有用户的 key
    for user_home in /root /home/*; do
        if [ -d "$user_home/.ssh" ]; then
            key_file="$user_home/.ssh/authorized_keys"
            if [ -f "$key_file" ]; then
                echo "--- 用户: $(basename $user_home) ---"
                cat "$key_file"
                echo
            fi
        fi
    done

    print_info "SSH 后门/劫持配置检查:"
    [ -f /root/.ssh/rc ] && echo "警告: 发现 /root/.ssh/rc" && cat /root/.ssh/rc
    [ -f /etc/ssh/sshrc ] && echo "警告: 发现 /etc/ssh/sshrc" && cat /etc/ssh/sshrc
    show_progress
}

check_persistence() {
    print_section "6. 持久化与维权痕迹 (Persistence)"
    
    print_info "系统定时任务 (System Cron):"
    cat /etc/crontab
    ls -l /etc/cron.d/

    print_info "用户定时任务 (User Crontab):"
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -l -u $user 2>/dev/null | grep -v "^#" | grep -q . && echo "User: $user" && crontab -l -u $user
    done

    print_info "可疑定时任务内容 (Reverse Shell Check):"
    grep -rnE "curl|wget|lynx|bash -i|/dev/tcp|nc " /var/spool/cron/ /etc/cron* 2>/dev/null

    print_info "开机启动项 (Systemd Enabled):"
    systemctl list-unit-files --type=service | grep enabled

    print_info "rc.local 内容:"
    [ -f /etc/rc.local ] && cat /etc/rc.local
    [ -f /etc/rc.d/rc.local ] && cat /etc/rc.d/rc.local
    show_progress
}

check_file_integrity() {
    print_section "7. 文件完整性与敏感文件 (File Integrity)"
    
    print_info "关键系统命令完整性 (RPM/DPKG Verify):"
    COMMANDS="ls ps netstat ss top login sshd"
    if command -v rpm >/dev/null; then
        for cmd in $COMMANDS; do
            path=$(which $cmd 2>/dev/null)
            if [ -n "$path" ]; then
                rpm -Vf "$path" >/dev/null && echo "$cmd: OK" || echo "警告: $cmd 校验失败 (可能被篡改)"
            fi
        done
    else
        echo "非 RPM 系统，跳过自动校验，建议使用 debsums。"
    fi

    print_info "危险的 SUID 文件 (提权风险):"
    find / -user root -perm -4000 -print 2>/dev/null | grep -vE "snap|/usr/bin/sudo|/usr/bin/passwd|/usr/bin/su|/usr/bin/mount|/usr/bin/umount|/usr/bin/chsh|/usr/bin/newgrp" | head -n 20

    print_info "临时目录下可疑脚本 (/tmp, /var/tmp):"
    find /tmp /var/tmp -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.elf" 2>/dev/null

    print_info "最近 3 天内变动的 /usr/bin 文件:"
    find /usr/bin /usr/sbin -type f -mtime -3 2>/dev/null

    print_info "关键文件属性锁定 (lsattr):"
    lsattr /etc/passwd /etc/shadow 2>/dev/null
    show_progress
}

check_logs() {
    print_section "8. 日志分析 (Log Analysis)"
    
    if [ -f "$AUTH_LOG" ]; then
        print_info "最近 10 次成功登录:"
        grep "Accepted " "$AUTH_LOG" | awk '{print $1,$2,$3,$9,$11}' | tail -n 10
        
        print_info "登录成功 IP 统计 (Top 5):"
        grep "Accepted " "$AUTH_LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 5
        
        print_info "登录失败 IP 统计 (Top 5 - 暴力破解来源):"
        grep "Failed password" "$AUTH_LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 5
        
        print_info "账号创建/删除操作:"
        grep -E "useradd|userdel|groupadd" "$AUTH_LOG"
    else
        echo "未找到认证日志文件。"
    fi

    print_info "历史命令中的敏感操作 (History Check):"
    if [ -f /root/.bash_history ]; then
        grep -E "wget |curl |nc |tar |zip |passwd " /root/.bash_history | tail -n 10
    fi
    show_progress
}

# ================= 开始执行 =================

echo "========================================================" >&3
echo -e "${GREEN}Linux 黑客入侵痕迹排查脚本${NC}" >&3
echo "========================================================" >&3
echo "报告将保存至: $OUTPUT" >&3
echo "开始时间: $(date)" >&3
echo >&3

# 循环执行所有检查函数
for check in "${CHECKS[@]}"; do
    $check
done

echo -e "\n\n========================================================" >&3
echo -e "${GREEN}检查完毕！${NC}" >&3
echo "请详细查看生成的文件: $OUTPUT" >&3
echo "重点关注包含 '警告'、'Error' 或 'Deleted' 的内容。" >&3
echo "========================================================" >&3

# 恢复标准输出
exec 3>&-
