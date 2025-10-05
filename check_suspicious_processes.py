# check_suspicious_processes.py
# 功能：检查Windows系统中可疑的异常进程
# 需要安装 psutil: pip install psutil

import psutil
import os
import re
import sys

# 常见的恶意进程名称或关键词（可扩展）
MALICIOUS_KEYWORDS = [
    'hack', 'keylog', 'spy', 'remote', 'vnc', 'rat', 'trojan',
    'meterpreter', 'cobalt', 'shell', 'reverse', 'backdoor'
]

# 正常的系统进程路径（白名单）
SYSTEM_PATHS = [
    r'C:\Windows\System32',
    r'C:\Windows\SysWOW64',
    r'C:\Windows\Explorer.EXE',
    r'\??\C:\Windows\System32'  # 对应 ntoskrnl 等
]

# 常见被仿冒的系统进程（注意拼写错误）
SUSPICIOUS_NAMES = {
    'svchost.exe': ['svch0st.exe', 'scvhost.exe', 'svchosts.exe'],
    'lsass.exe': ['lsasss.exe', 'lssas.exe'],
    'winlogon.exe': ['winlogonn.exe', 'winlogin.exe'],
    'explorer.exe': ['explorerr.exe', 'explorerx.exe', 'explorer_.exe'],
    'csrss.exe': ['csrsss.exe', 'csrss1.exe'],
    'smss.exe': ['smsss.exe', 'sms.exe']
}

# 高风险运行路径（攻击者常用来隐藏进程）
HIGH_RISK_PATHS = [
    'Temp', 'AppData\\Local\\Temp', 'Downloads', 'Desktop',
    '\\AppData\\Roaming\\', '\\Local\\Programs\\', '.cache'
]


def is_system_process(proc_path):
    """判断是否为系统可信路径"""
    if not proc_path:
        return False
    proc_path = os.path.normpath(proc_path).lower()
    for trusted in SYSTEM_PATHS:
        if proc_path.startswith(os.path.normpath(trusted).lower()):
            return True
    return False


def is_suspicious_name(process_name):
    """检查进程名是否是仿冒系统进程"""
    issues = []
    for good_name, bad_variants in SUSPICIOUS_NAMES.items():
        if process_name.lower() in [v.lower() for v in bad_variants]:
            issues.append(f"疑似仿冒 {good_name}")
    return issues


def has_malicious_keyword(process_name, proc_path=""):
    """检查是否包含恶意关键词"""
    full_text = (process_name + " " + proc_path).lower()
    found = []
    for keyword in MALICIOUS_KEYWORDS:
        if keyword.lower() in full_text:
            found.append(keyword)
    return found


def is_high_risk_path(proc_path):
    """检查是否在高风险路径运行"""
    if not proc_path:
        return False
    proc_path = proc_path.lower()
    for risk_path in HIGH_RISK_PATHS:
        if risk_path.lower() in proc_path:
            return True
    return False


def get_running_processes():
    """获取所有正在运行的进程信息"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe = proc.info['exe'] or "Unknown"
            name = proc.info['name']
            username = proc.info['username']
            processes.append({
                'pid': proc.info['pid'],
                'name': name,
                'exe': exe,
                'username': username
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes


def main():
    print("=" * 60)
    print("🔍 正在扫描可疑进程...")
    print("=" * 60)

    all_processes = get_running_processes()
    print(f"✅ 共发现 {len(all_processes)} 个运行中的进程。")

    # 统计同名进程数量
    name_count = {}
    for p in all_processes:
        name_count[p['name']] = name_count.get(p['name'], 0) + 1

    suspicious_found = False

    print("\n" + "-" * 60)
    print("🚨 检查可疑进程...")
    print("-" * 60)

    for proc in all_processes:
        issues = []

        # 1. 检查是否仿冒系统进程名
        name_issues = is_suspicious_name(proc['name'])
        if name_issues:
            issues.extend(name_issues)

        # 2. 检查恶意关键词
        keywords = has_malicious_keyword(proc['name'], proc['exe'])
        if keywords:
            issues.append(f"包含恶意关键词: {', '.join(keywords)}")

        # 3. 检查高风险路径
        if is_high_risk_path(proc['exe']):
            issues.append(f"运行于高风险路径: {proc['exe']}")

        # 4. 非系统路径运行的系统级进程名（如 svchost 在 Temp）
        if proc['name'].lower() in SUSPICIOUS_NAMES.keys() or proc['name'].lower() in ['dllhost.exe']:
            if not is_system_process(proc['exe']):
                issues.append(f"系统进程名但不在系统路径: {proc['exe']}")

        # 5. 多个同名非系统进程（如多个 python.exe 在用户目录）
        if name_count[proc['name']] > 3:  # 超过3个视为可疑
            if is_high_risk_path(proc['exe']) or 'python' in proc['name'].lower():
                issues.append(f"存在 {name_count[proc['name']]} 个同名进程，可能异常")

        # 输出警告
        if issues:
            suspicious_found = True
            print(f"⚠️  PID [{proc['pid']}] 名称 [{proc['name']}] 用户: {proc['username']}")
            for issue in issues:
                print(f"     🔸 {issue}")

    if not suspicious_found:
        print("✅ 未发现明显可疑进程。")
    else:
        print("\n🔔 建议：对上述进程进行进一步调查，可通过任务管理器或杀毒软件分析。")

    print("\n" + "=" * 60)
    print("✅ 进程检查完成。")
    print("=" * 60)


if __name__ == "__main__":
    main()