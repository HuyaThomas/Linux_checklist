# Linux_checklist

一个用于快速检查 Linux 系统常见安全与运行情况的脚本：Linux_checklist.sh。脚本将输出写入以日期命名的文本文件，终端显示简易进度条。

## 主要检查项：
- 用户与 sudo 授权
- 登录与审计日志（lastlog、secure 等）
- shell history
- 网络连接与监听端口（netstat / 可替换为 ss）
- 运行进程与服务
- crontab 与定时任务
- SSH authorized_keys
- 开机启动项与内核模块
- 常见敏感目录（cron、rc.d、anacron 等）

## 安全与合规：
- 脚本会导出敏感信息，仅在授权环境运行并妥善保管输出文件。
