# 导入所需的模块
import requests  # 用于发送 HTTP 请求
import json  # 用于处理 JSON 数据
import IPy  # 用于处理 IP 地址和 CIDR 范围
import config  # 自定义配置模块，包含 API Token 和其他配置信息

# 设置请求头，包含认证信息和内容类型
headers = {
    "Authorization": "Bearer " + config.linode_token,  # 使用配置文件中的 Linode API Token
    "Content-Type": "application/json"  # 设置请求内容类型为 JSON
}

# 获取指定区域的实例私有 IP 地址
def get_instances(region: str):
    """
    获取指定区域的实例私有 IP 地址。
    遍历指定区域的所有实例，提取属于指定 CIDR 范围的私有 IP 地址。
    
    参数:
        region (str): 目标区域名称（如 'ap-south'）
    
    返回:
        list: 区域内实例的私有 IP 地址列表，格式为 'IP/32'
    """
    url = config.instances_url  # 实例信息的 API URL
    linode_cidr = config.linode_cidr  # 指定的 CIDR 范围

    page = 1  # 初始化分页参数
    private_ips = []  # 用于存储私有 IP 地址的列表

    # 循环分页获取实例信息
    while True:
        params = {
            'page': page,  # 当前页码
            'page_size': config.pagesize  # 每页的实例数量
        }
        resp = requests.get(url, headers=headers, params=params)  # 发送 GET 请求
        data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

        page = data['page']  # 获取当前页码
        pages = data['pages']  # 获取总页数

        # 遍历当前页的实例数据
        for item in data['data']:
            if item['region'] == region:  # 检查实例是否属于指定区域
                for ip in item['ipv4']:  # 遍历实例的 IPv4 地址
                    if ip in IPy.IP(linode_cidr):  # 检查 IP 是否属于指定的 CIDR 范围
                        cidr_ip = ip + "/32"  # 将 IP 地址转换为 /32 格式
                        private_ips.append(cidr_ip)  # 添加到私有 IP 列表

        if page == pages:  # 如果已获取所有页的数据，退出循环
            break
        page += 1  # 继续下一页

    return private_ips  # 返回私有 IP 地址列表

# 根据防火墙标签获取防火墙 ID
def get_firewall_id(label: str):
    """
    根据防火墙标签获取防火墙 ID。
    遍历所有防火墙，查找匹配的标签并返回对应的防火墙 ID。
    
    参数:
        label (str): 防火墙的标签名称
    
    返回:
        int or None: 防火墙的 ID，如果未找到则返回 None
    """
    url = config.firewalls_url  # 防火墙信息的 API URL
    resp = requests.get(url, headers=headers)  # 发送 GET 请求
    data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

    firewall_id = None  # 初始化防火墙 ID 为 None
    # 遍历防火墙列表，查找匹配的标签
    for item in data['data']:
        if item['label'] == label:
            firewall_id = item['id']  # 如果找到匹配的标签，记录防火墙 ID
            break

    return firewall_id  # 返回防火墙 ID

# 获取指定防火墙的规则
def get_firewall_rules(firewall_id):
    """
    获取指定防火墙的规则。
    
    参数:
        firewall_id (int): 防火墙的 ID
    
    返回:
        dict: 防火墙的规则数据
    """
    url = config.fw_rules_url.replace('{firewallId}', str(firewall_id))  # 替换 URL 中的防火墙 ID 占位符
    resp = requests.get(url, headers=headers)  # 发送 GET 请求
    return json.loads(resp.text)  # 解析响应数据为 JSON 格式并返回

# 更新指定防火墙的规则
def update_firewall_rules(firewall_id, rules):
    """
    更新指定防火墙的规则。
    
    参数:
        firewall_id (int): 防火墙的 ID
        rules (dict): 新的规则数据
    
    返回:
        dict: 更新后的防火墙规则数据
    """
    url = config.fw_rules_url.replace('{firewallId}', str(firewall_id))  # 替换 URL 中的防火墙 ID 占位符
    resp = requests.put(url, headers=headers, data=json.dumps(rules))  # 发送 PUT 请求更新规则
    return json.loads(resp.text)  # 解析响应数据为 JSON 格式并返回

# 更新防火墙规则以允许指定的 IP 列表
def update_firewall(firewall_id, ip_list):
    """
    更新防火墙规则以允许指定的 IP 列表。
    生成新的 TCP 和 UDP 规则，并更新防火墙的入站规则。
    
    参数:
        firewall_id (int): 防火墙的 ID
        ip_list (list): 允许的 IP 地址列表
    
    返回:
        dict: 更新后的防火墙规则数据
    """
    rules = get_firewall_rules(firewall_id)  # 获取当前防火墙的规则
    inbound_policy = []  # 初始化入站规则列表

    # 遍历现有规则，保留非自动生成的规则
    for rule in rules['inbound']:
        if rule['label'] != 'accept-region-inbound-policy':
            inbound_policy.append(rule)

    # 如果 IP 列表为空，跳过规则更新
    if not ip_list:
        print("No valid IPs found. Skipping rule update.")
        return

    # 添加新的 TCP 和 UDP 规则
    tcp_rule = {
        "protocol": "TCP",
        "ports": "1-65535",
        "addresses": {
            "ipv4": ip_list
        },
        "action": "ACCEPT",
        "label": "accept-region-inbound-policy",
        "description": "Auto-generated local region inbound rules."
    }
    udp_rule = {
        "protocol": "UDP",
        "ports": "1-65535",
        "addresses": {
            "ipv4": ip_list
        },
        "action": "ACCEPT",
        "label": "accept-region-inbound-policy",
        "description": "Auto-generated local region inbound rules."
    }

    inbound_policy.append(tcp_rule)  # 添加 TCP 规则
    inbound_policy.append(udp_rule)  # 添加 UDP 规则

    rules['inbound'] = inbound_policy  # 更新入站规则
    return update_firewall_rules(firewall_id, rules)  # 调用更新规则函数

# 清理防火墙规则中不再存在的 IP 地址
def remove_unused_ips(firewall_id, current_ips):
    """
    清理防火墙规则中不再存在的 IP 地址。
    比较当前实例的 IP 地址列表和防火墙规则中的 IP 地址列表，删除不再存在的 IP 地址。
    
    参数:
        firewall_id (int): 防火墙的 ID
        current_ips (list): 当前有效的 IP 地址列表
    
    返回:
        dict: 更新后的防火墙规则数据
    """
    rules = get_firewall_rules(firewall_id)  # 获取当前防火墙的规则
    inbound_policy = []  # 初始化入站规则列表

    # 遍历现有规则，保留非自动生成的规则
    for rule in rules['inbound']:
        if rule['label'] != 'accept-region-inbound-policy':
            inbound_policy.append(rule)
        else:
            # 检查规则中的 IP 地址是否仍然有效
            existing_ips = rule['addresses']['ipv4']
            updated_ips = [ip for ip in existing_ips if ip in current_ips]

            # 如果 IP 地址列表发生变化，更新规则
            if updated_ips != existing_ips:
                rule['addresses']['ipv4'] = updated_ips
                print(f"Updated IP list for rule '{rule['label']}': {updated_ips}")

            # 如果更新后的 IP 列表为空，跳过规则更新
            if not updated_ips:
                print(f"No valid IPs for rule '{rule['label']}'. Skipping rule update.")
                continue

            inbound_policy.append(rule)

    rules['inbound'] = inbound_policy  # 更新入站规则
    return update_firewall_rules(firewall_id, rules)  # 调用更新规则函数

# 主程序逻辑
def main():
    """
    主程序逻辑：
    1. 获取指定区域的实例私有 IP 地址。
    2. 获取防火墙 ID。
    3. 更新防火墙规则以匹配当前实例的 IP 地址。
    4. 清理防火墙规则中不再存在的 IP 地址。
    """
    region = config.region  # 从配置文件中获取目标区域
    firewall_name = f"{region}_firewall_policy"  # 构造防火墙名称

    # 获取实例的私有 IP 地址
    ip_list = get_instances(region)
    print(f"Region: {region}, IPs: {ip_list}")

    # 获取防火墙 ID
    firewall_id = get_firewall_id(firewall_name)

    if firewall_id:
        print(f"Firewall '{firewall_name}' already exists.")
        print("Updating rules to match current instances...")
        update_result = update_firewall(firewall_id, ip_list)
        print(f"Update result: {update_result}")

        print("Cleaning up unused IP addresses...")
        cleanup_result = remove_unused_ips(firewall_id, ip_list)
        print(f"Cleanup result: {cleanup_result}")
    else:
        print(f"Firewall '{firewall_name}' not found. No action taken.")

    print("Task completed. Exiting...")

if __name__ == '__main__':
    main()  # 执行主程序
