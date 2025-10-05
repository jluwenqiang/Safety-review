# check_backdoor_users.py
# 功能：检查Windows系统中可疑的后门用户账户
# 运行方式：需以管理员权限运行

import subprocess
import re
import sys

def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return subprocess.check_output(['net', 'session'], stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return False

def get_users():
    """获取所有用户列表"""
    try:
        result = subprocess.check_output('net user', shell=True, text=True, encoding='gbk', errors='ignore')
        lines = result.splitlines()
        users = []
        capture = False
        for line in lines:
            if '----------' in line:
                capture = True
                continue
            if capture and line.strip() and not line.startswith('命令成功完成'):
                # 提取用户名（可能有多个）
                names = re.split(r'\s{2,}', line.strip())
                for name in names:
                    if name:
                        users.append(name.strip())
        return users
    except Exception as e:
        print(f"获取用户列表失败: {e}")
        return []

def get_user_info(username):
    """获取指定用户详细信息"""
    try:
        result = subprocess.check_output(f'net user "{username}"', shell=True, text=True, encoding='gbk', errors='ignore')
        return result
    except Exception as e:
        return ""

def is_hidden_user(username):
    """判断是否为隐藏用户（以$结尾）"""
    return username.endswith('$')

def is_builtin_admin(username):
    """判断是否为内置管理员（如Administrator）"""
    builtin = ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']
    return username in builtin

def is_member_of_administrators(username):
    """检查用户是否属于管理员组"""
    try:
        result = subprocess.check_output(f'net user "{username}"', shell=True, text=True, encoding='gbk', errors='ignore')
        return 'Administrators' in result or '管理员' in result
    except:
        return False

def check_suspicious_user(username):
    """检查用户是否可疑"""
    info = get_user_info(username)
    suspicious = []

    if is_hidden_user(username):
        suspicious.append("隐藏账户（用户名以$结尾）")

    if is_member_of_administrators(username) and not is_builtin_admin(username):
        suspicious.append("自定义管理员账户")

    # 检查是否为新创建的账户（可根据时间判断，此处简化）
    if '创建时间' in info:
        # 可进一步解析创建时间，判断是否为近期创建
        pass

    return suspicious

def main():
    print("=" * 60)
    print("🔍 正在检查系统后门用户账户...")
    print("=" * 60)

    if not is_admin():
        print("❌ 错误：请以管理员权限运行此脚本！")
        print("💡 右键点击脚本，选择“以管理员身份运行”")
        sys.exit(1)

    users = get_users()
    if not users:
        print("❌ 未能获取用户列表，请检查权限或系统环境。")
        sys.exit(1)

    print(f"✅ 共发现 {len(users)} 个用户账户：")
    for user in users:
        print(f"  - {user}")

    print("\n" + "-" * 60)
    print("🚨 检查可疑账户...")
    print("-" * 60)

    found_suspicious = False
    for user in users:
        issues = check_suspicious_user(user)
        if issues:
            found_suspicious = True
            print(f"⚠️  警告：用户 [{user}] 存在可疑特征：")
            for issue in issues:
                print(f"     🔸 {issue}")

    if not found_suspicious:
        print("✅ 未发现明显可疑的后门用户账户。")

    print("\n" + "=" * 60)
    print("✅ 安全检查完成。")
    print("=" * 60)

if __name__ == "__main__":
    main()