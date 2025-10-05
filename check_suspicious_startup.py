# check_suspicious_startup.py
# 功能：检查Windows系统中的异常启动项（注册表 + 启动文件夹）
# 需要管理员权限运行

import winreg
import os
import sys
import glob

# 常见恶意关键词
MALICIOUS_KEYWORDS = ['hack', 'keylog', 'spy', 'remote', 'rat', 'trojan', 'backdoor', 'shell', 'vnc', 'miner']

# 高风险路径（攻击者常用来隐藏启动项）
HIGH_RISK_PATHS = [
    'Temp', 'AppData\\Local\\Temp', 'AppData\\Roaming',
    'Downloads', 'Desktop', '\\Local\\Programs\\', '.cache'
]

# 正常可信的启动路径（白名单）
TRUSTED_PATHS = [
    r'C:\Windows', r'C:\Program Files', r'C:\Program Files (x86)',
    r'\??\C:\Windows'
]

# 常见被仿冒的启动项名称
SUSPICIOUS_NAMES = [
    'svchost', 'explorer', 'winlogon', 'lsass', 'csrss', 'smss'
]


def is_high_risk_path(path):
    """判断路径是否在高风险目录"""
    if not path:
        return False
    path = path.lower()
    for risk in HIGH_RISK_PATHS:
        if risk.lower() in path:
            return True
    return False


def is_trusted_path(path):
    """判断是否为可信路径"""
    if not path:
        return False
    path = os.path.normpath(path).lower()
    for trusted in TRUSTED_PATHS:
        if path.startswith(os.path.normpath(trusted).lower()):
            return True
    return False


def has_malicious_keyword(text):
    """检查是否包含恶意关键词"""
    text = text.lower()
    return [kw for kw in MALICIOUS_KEYWORDS if kw.lower() in text]


def is_suspicious_name(name):
    """检查名称是否仿冒系统进程"""
    name_lower = name.lower()
    for sys_name in SUSPICIOUS_NAMES:
        if sys_name in name_lower and (name_lower.count('0') or name_lower.count('1') or '_' in name_lower):
            return True
    return False


def query_registry_run_keys():
    """查询注册表中的启动项"""
    startup_items = []
    # 注册表启动项路径
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for hkey, subkey in reg_paths:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_items.append({
                            'type': 'Registry',
                            'name': name,
                            'value': value,
                            'path': subkey
                        })
                        i += 1
                    except OSError:
                        break  # 枚举结束
        except PermissionError:
            print(f"⚠️  无权限访问注册表路径: {subkey}")
        except Exception as e:
            print(f"❌ 访问注册表失败 {subkey}: {e}")

    return startup_items


def get_startup_folder_items():
    """获取启动文件夹中的快捷方式或可执行文件"""
    startup_items = []
    # 用户启动文件夹
    user_startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    # 全局启动文件夹
    common_startup = os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")

    folders = [('User Startup', user_startup), ('Common Startup', common_startup)]

    for location, folder_path in folders:
        if not os.path.exists(folder_path):
            continue
        # 查找 .exe, .bat, .vbs, .lnk 等可疑文件
        patterns = ['*.exe', '*.bat', '*.vbs', '*.ps1', '*.lnk', '*.cmd']
        for pattern in patterns:
            for file_path in glob.glob(os.path.join(folder_path, pattern)):
                if os.path.isfile(file_path):
                    startup_items.append({
                        'type': 'Startup Folder',
                        'name': os.path.basename(file_path),
                        'value': file_path,
                        'path': location
                    })
    return startup_items


def main():
    print("=" * 60)
    print("🔍 正在扫描异常启动项...")
    print("=" * 60)

    # 检查权限
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software")
    except PermissionError:
        print("❌ 错误：请以管理员权限运行此脚本！")
        print("💡 右键 PyCharm 或脚本，选择“以管理员身份运行”")
        sys.exit(1)

    all_items = []

    # 1. 检查注册表启动项
    print("📁 正在扫描注册表启动项...")
    reg_items = query_registry_run_keys()
    all_items.extend(reg_items)
    print(f"✅ 注册表中发现 {len(reg_items)} 个启动项。")

    # 2. 检查启动文件夹
    print("📁 正在扫描启动文件夹...")
    folder_items = get_startup_folder_items()
    all_items.extend(folder_items)
    print(f"✅ 启动文件夹中发现 {len(folder_items)} 个启动项。")

    print("\n" + "-" * 60)
    print("🚨 检查可疑启动项...")
    print("-" * 60)

    suspicious_found = False

    for item in all_items:
        issues = []

        # 提取可执行路径（从注册表值或文件路径中解析）
        value = item['value']
        exe_path = value
        # 简单提取路径（如 "C:\xxx\abc.exe" 参数 -> 提取带exe的部分）
        import re
        match = re.search(r'(["\']?)([A-Za-z]:\\[^"\']+\.(exe|bat|vbs|ps1|cmd))\1', value)
        if match:
            exe_path = match.group(2)
        else:
            exe_path = value  # 保守处理

        # 1. 检查高风险路径
        if is_high_risk_path(exe_path):
            issues.append(f"位于高风险路径: {exe_path}")

        # 2. 检查是否不在可信路径且不是系统目录
        if not is_trusted_path(exe_path) and is_high_risk_path(exe_path):
            issues.append(f"非可信路径运行: {exe_path}")

        # 3. 检查恶意关键词
        keywords = has_malicious_keyword(value)
        if keywords:
            issues.append(f"包含恶意关键词: {', '.join(keywords)}")

        # 4. 检查名称是否可疑
        if is_suspicious_name(item['name']):
            issues.append(f"疑似仿冒系统启动项: {item['name']}")

        # 输出警告
        if issues:
            suspicious_found = True
            print(f"⚠️  [{item['type']}] 名称: {item['name']}")
            for issue in issues:
                print(f"     🔸 {issue}")

    if not suspicious_found:
        print("✅ 未发现明显可疑的启动项。")
    else:
        print("\n🔔 建议：对上述启动项进行进一步调查，可通过任务管理器或注册表编辑器禁用。")

    print("\n" + "=" * 60)
    print("✅ 启动项检查完成。")
    print("=" * 60)


if __name__ == "__main__":
    main()