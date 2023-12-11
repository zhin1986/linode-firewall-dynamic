# Personal Access Token
linode_token = ''

# Target Region
region = 'ap-south'

# Refresh Invertal, seconds
interval = 5
pagesize = 200

# Auto bind firewall with instance in the target region
# Not Implemented
bind_instance = False   


######################################################################
#                   Don't modify the following code                  #
######################################################################
instances_url = 'https://api.linode.com/v4/linode/instances'
firewalls_url = 'https://api.linode.com/v4/networking/firewalls'
fw_rules_url = 'https://api.linode.com/v4/networking/firewalls/{firewallId}/rules'

linode_cidr = '192.168.128.0/17'

linode_firewall = { 
    "label": "", 
    "rules": { 
        "inbound_policy": "DROP", 
        "inbound": [ ],
        "outbound_policy": "ACCEPT",
        "outbound": [ ]
    },
    "devices": {
        "linodes": [ ]
    },
    "tags": [
        "WANSHI"
    ]
}

