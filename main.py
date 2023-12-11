import requests, json, time
import IPy
import config

headers = {
    "Authorization": "Bearer " + config.linode_token,
    "Content-Type": "application/json"
}


def GetInstances(region: str):
    url = config.instances_url
    linode_cidr = config.linode_cidr

    page = 1
    private_ips = []

    while True:

        param = {
            'page': page,
            'page_size': config.pagesize
        }

        resp = requests.get(url, 
                            headers=headers, 
                            params=param)
        #print(page, resp.status_code)
        data = json.loads(resp.text)

        page = data['page']
        pages = data['pages']

        for item in data['data']:
            if(item['region'] == region):
                for ip in item['ipv4']:
                    if ip in IPy.IP(linode_cidr):
                        cidr_ip = ip + "/32"
                        private_ips.append(cidr_ip)

        if page == pages:
            break
    
    return private_ips



def GetFirewalls(label: str):
    url = config.firewalls_url
    resp = requests.get(url, 
                        headers=headers)
    data = json.loads(resp.text)

    firewall_id = 0
    for item in data['data']:
        if item['label'] == label:
            firewall_id = item['id']
    
    return firewall_id


def GetFirewallRules(id):
    url = config.fw_rules_url
    url = url.replace('{firewallId}', str(id))

    resp = requests.get(url, 
                        headers=headers)
    data = json.loads(resp.text)

    return data


def UpdateFirewallRules(id, rules):
    url = config.fw_rules_url
    url = url.replace('{firewallId}', str(id))

    resp = requests.put(url, 
                        headers=headers,
                        data=json.dumps(rules))
    data = json.loads(resp.text)

    return data



def UpdateFirewall(id: str, ip_list):
    inbound_policy = []

    rules = GetFirewallRules(id)
    
    for rule in rules['inbound']:
        if rule['label'] != 'accept-region-inbound-policy':
            inbound_policy.append(rule)
        
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
    
    inbound_policy.append(tcp_rule)
    inbound_policy.append(udp_rule)
    
    rules['inbound'] = inbound_policy

    return UpdateFirewallRules(id, rules)



def CreateFirewall(name: str, ip_list):

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

    firewall = config.linode_firewall
    firewall['rules']['inbound'] = rules
    firewall['label'] = name

    resp = requests.post(url=config.firewalls_url, 
                        headers=headers, 
                        data=json.dumps(firewall))
    data = json.loads(resp.text)

    return data

    


if __name__ == '__main__':

    inteval = config.interval
    while True:
        region = config.region
        ip_list = GetInstances(region)
        print(region,ip_list)

        firewall_name = config.region + '_firewall_policy'
        firewall_id = GetFirewalls(firewall_name)

        if firewall_id == 0:
            print('Create Firewall')
            result = CreateFirewall(firewall_name, ip_list)

        else:
            print('Update Firewall')
            result = UpdateFirewall(firewall_id, ip_list)

        print(result)

        time.sleep(inteval)




