# 导入所需的模块
import requests, json, time
import IPy
import config

# 设置请求头，包含认证信息和内容类型
headers = {
    "Authorization": "Bearer " + config.linode_token,  # 使用配置文件中的 Linode API Token
    "Content-Type": "application/json"
}

# 获取指定区域的实例私有 IP 地址
def GetInstances(region: str):
    url = config.instances_url  # 实例信息的 API URL
    linode_cidr = config.linode_cidr  # 指定的 CIDR 范围

    page = 1  # 初始化分页参数
    private_ips = []  # 用于存储私有 IP 地址的列表

    # 循环分页获取实例信息
    while True:
        param = {
            'page': page,  # 当前页码
            'page_size': config.pagesize  # 每页的实例数量
        }

        # 发送 GET 请求获取实例信息
        resp = requests.get(url, headers=headers, params=param)
        data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

        # 遍历当前页的实例数据
        for item in data['data']:
            if item['region'] == region:  # 检查实例是否属于指定区域
                for ip in item['ipv4']:  # 遍历实例的 IPv4 地址
                    if ip in IPy.IP(linode_cidr):  # 检查 IP 是否属于指定的 CIDR 范围
                        cidr_ip = ip + "/32"  # 将 IP 地址转换为 /32 格式
                        private_ips.append(cidr_ip)  # 添加到私有 IP 列表

        # 检查是否已获取所有页的数据
        if page == data['pages']:
            break
        page += 1  # 如果未完成，继续下一页

    return private_ips  # 返回私有 IP 地址列表


# 根据防火墙标签获取防火墙 ID
def GetFirewalls(label: str):
    url = config.firewalls_url  # 防火墙信息的 API URL

    # 发送 GET 请求获取防火墙列表
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

    firewall_id = 0  # 初始化防火墙 ID 为 0（表示未找到）
    # 遍历防火墙列表，查找匹配的标签
    for item in data['data']:
        if item['label'] == label:
            firewall_id = item['id']  # 如果找到匹配的标签，记录防火墙 ID
            break

    return firewall_id  # 返回防火墙 ID


# 获取指定防火墙的规则
def GetFirewallRules(id):
    url = config.fw_rules_url  # 防火墙规则的 API URL
    url = url.replace('{firewallId}', str(id))  # 替换 URL 中的防火墙 ID 占位符

    # 发送 GET 请求获取防火墙规则
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

    return data  # 返回防火墙规则


# 更新指定防火墙的规则
def UpdateFirewallRules(id, rules):
    url = config.fw_rules_url  # 防火墙规则的 API URL
    url = url.replace('{firewallId}', str(id))  # 替换 URL 中的防火墙 ID 占位符

    # 发送 PUT 请求更新防火墙规则
    resp = requests.put(url, headers=headers, data=json.dumps(rules))
    data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

    return data  # 返回更新后的防火墙规则


# 更新防火墙规则以允许指定的 IP 列表
def UpdateFirewall(id: str, ip_list):
    inbound_policy = []  # 初始化入站规则列表

    # 获取当前防火墙的规则
    rules = GetFirewallRules(id)

    # 遍历当前规则，保留非自动生成的规则
    for rule in rules['inbound']:
        if rule['label'] != 'accept-region-inbound-policy':
            inbound_policy.append(rule)

    # 添加允许 TCP 和 UDP 的所有端口的规则
    tcp_rule = {
        "protocol": "TCP",
        "ports": "1-65535",
        "addresses": {
            "ipv4": ip_list
        },
        "action": "ACCEPT",
        "label": "accept-region-inbound-policy",
        "description": "Auto generated local region inbound rules."
    }
    udp_rule = {
        "protocol": "UDP",
        "ports": "1-65535",
        "addresses": {
            "ipv4": ip_list
        },
        "action": "ACCEPT",
        "label": "accept-region-inbound-policy",
        "description": "Auto generated local region inbound rules."
    }

    inbound_policy.append(tcp_rule)  # 添加 TCP 规则
    inbound_policy.append(udp_rule)  # 添加 UDP 规则

    # 更新规则
    rules['inbound'] = inbound_policy

    # 调用 UpdateFirewallRules 函数更新防火墙规则
    return UpdateFirewallRules(id, rules)


# 创建新的防火墙
def CreateFirewall(name: str, ip_list):
    # 定义允许 TCP 和 UDP 的所有端口的规则
    rules = [
        {
            "protocol": "TCP",
            "ports": "1-65535",
            "addresses": {
                "ipv4": ip_list
            },
            "action": "ACCEPT",
            "label": "accept-region-inbound-policy",
            "description": "Auto generated local region inbound rules."
        },
        {
            "protocol": "UDP",
            "ports": "1-65535",
            "addresses": {
                "ipv4": ip_list
            },
            "action": "ACCEPT",
            "label": "accept-region-inbound-policy",
            "description": "Auto generated local region inbound rules."
        }
    ]

    # 从配置文件中获取防火墙模板
    firewall = config.linode_firewall
    firewall['rules']['inbound'] = rules  # 设置入站规则
    firewall['label'] = name  # 设置防火墙名称

    # 发送 POST 请求创建防火墙
    resp = requests.post(url=config.firewalls_url, headers=headers, data=json.dumps(firewall))
    data = json.loads(resp.text)  # 解析响应数据为 JSON 格式

    return data  # 返回创建的防火墙信息


# 主程序入口
if __name__ == '__main__':
    interval = config.interval  # 从配置文件中获取定时任务的间隔时间

    # 无限循环，定时执行任务
    while True:
        region = config.region  # 从配置文件中获取目标区域
        ip_list = GetInstances(region)  # 获取指定区域的实例私有 IP 列表
        print(region, ip_list)  # 打印区域和 IP 列表

        firewall_name = config.region + '_firewall_policy'  # 构造防火墙名称
        firewall_id = GetFirewalls(firewall_name)  # 获取防火墙 ID

        # 根据防火墙是否存在，执行创建或更新操作
        if firewall_id == 0:
            print('Create Firewall')  # 如果防火墙不存在，创建防火墙
            result = CreateFirewall(firewall_name, ip_list)
        else:
            print('Update Firewall')  # 如果防火墙已存在，更新防火墙规则
            result = UpdateFirewall(firewall_id, ip_list)

        print(result)  # 打印操作结果

        time.sleep(interval)  # 按配置的间隔时间暂停
