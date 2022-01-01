#!/usr/bin/python3
#
# Written by Ivelin Ivanov
#
### Description
# A Nutanix VM import script for Netbox written in Python.
#
### Do first:
# 1. Extract the JSON data for all VMs and Networks and name them 
#    clustername.json and clustername-nets.json
#    For ex. ntnx.json and ntnx-nets.json
# 2. Ensure the API Token is valid or renew before using.
#
### JSON corrections:
# 1. Change Vlan 0 to XXX in ntnx.json
# 2. Fix the missing IP addresses for a few VMs
# 3. Flipped interface order on some VMs
# 4. IP address duplication on the same interface
# Note: The IP address data provided by Nutanix is around 90% correct.
#
### ToDo:
# 1. Improve the Cluster ID lookup function
# 2. Improve the IP prefix lookup function, currently takes the last record
# 3. Add direct Nutanix REST API fetch instead of files
# 4. Create a JSON data patch, for data not found in Nutanix API (missing IPs, untagged VLAN ID 0, etc.)
#

from os import name
import sys
import re
import json
import string
import requests
import argparse
from requests.api import request
requests.packages.urllib3.disable_warnings()

from typing import Counter

ApiUrlBase = "https://netbox/api"
ApiUrlSubVlanIds = "/ipam/vlans/"
ApiUrlSubPrefixes = "/ipam/prefixes/"
ApiUrlSubClusters = "/virtualization/clusters/"
ApiUrlSubIpAdresses = "/ipam/ip-addresses/"
ApiUrlSubVMs = "/virtualization/virtual-machines/"
ApiUrlSubVMInterfaces = "/virtualization/interfaces/"
ApiUrlSubLimitResults="?limit=1000000"

ApiToken = "secret"
headers = {
    'Authorization': 'token {}'.format(ApiToken),
    'Content-Type': 'application/json'
}

try:
    FileVmsJson = sys.argv[1]
except Exception as e:
    print("The VM JSON file not set!\n" + str(e))
    sys.exit(2)

try:
    FileNetsJson = sys.argv[2]
except Exception as e:
    print("The Networks JSON file not set!\n" + str(e))
    sys.exit(2)


def main():
    """ Main function
    """
    print("Start main\n")
    
    VmsJson = LoadJson(FileVmsJson)
    NetsJson = LoadJson(FileNetsJson)['entities']
    NetboxVlanIdsJson = ApiGet(ApiUrlSubVlanIds)['results']
    NetboxPrefixesJson = ApiGet(ApiUrlSubPrefixes)['results']
    NetboxClustersJson = ApiGet(ApiUrlSubClusters)['results']
    
    for vm in VmsJson:
        if vm['power_state'] == 'off':
            continue
        
        ClustersId = NetboxGetClusterIdByName(FileVmsJson, NetboxClustersJson)

        JsonTemplateNewVM = {
                                "name": vm['name'],
                                "status": "active",
                                "cluster": ClustersId,
                                "role": 4,
                                "custom_fields": {
                                    "uuid": vm['uuid']
                                }
                            }
        #print(str(JsonTemplateNewVM))

        VmsId = ApiPost(ApiUrlSubVMs, JsonTemplateNewVM)
        print(VmsId)

        NicID = 0
        for nic in vm['vm_nics']:
            if nic['is_connected'] != True:
                continue
            
            Vid = NutanixGetVlanidByUuid(nic['network_uuid'], NetsJson)
            VlansId = NetboxGetVlanIdByVlanid(Vid, NetboxVlanIdsJson)
            MacAddr = nic['mac_address']

            JsonTemplateNewVMIface = {
                                "name": "NIC " + str(NicID),
                                "enabled": True,
                                "mgmt_only": False,
                                "mode": "access",
                                "untagged_vlan": VlansId,
                                "virtual_machine": VmsId,
                                "mac_address": MacAddr
                            }
            #print(str(JsonTemplateNewVMIface))
            VmIfacesId = ApiPost(ApiUrlSubVMInterfaces, JsonTemplateNewVMIface)
            print(VmIfacesId)

            if 'ip_addresses' in nic:
                for ip in nic['ip_addresses']:
                    NetMask = NetboxGetNetmaskByPrefix(ip, NetboxPrefixesJson)

                    JsonTemplateNewIpAddress = {
                        "address": str(ip) + "/" + str(NetMask),
                        "assigned_object_type": "virtualization.vminterface",
                        "assigned_object_id": VmIfacesId,
                        "status": "active"
                    }

                    #print(str(JsonTemplateNewIpAddress))
                    IpAddrId = ApiPost(ApiUrlSubIpAdresses, JsonTemplateNewIpAddress)
                    print(IpAddrId)

            NicID = NicID + 1
             

    print("End main\n")


def LoadJson (FileName):
    """ Read the JSON data from file
    """
    File = open(FileName)
    Json = json.load(File)

    return Json

def ApiGet (ApiUrlSub):
    """ A function to GET to the REST API, which accepts sub-URL and a JSON data variables
    """
    try:
        req = requests.get(ApiUrlBase + ApiUrlSub + ApiUrlSubLimitResults, headers=headers, timeout=15, verify=False)
    except Exception as e:
        print(str(e))
        sys.exit(2)
  
    return req.json()

def ApiPost (ApiUrlSub, JSON):
    """ A function to POST to the REST API, which accepts sub-URL and a JSON data variables
    """
    try:
        req = requests.post(ApiUrlBase + ApiUrlSub, headers=headers, timeout=15, verify=False, json=JSON)
    except Exception as e:
        print(str(e))
        sys.exit(2)
    
    return req.json()["id"]

def NetboxGetVlanIdByVlanid (Vlanid, NetboxVlanIdsJson):
    """ Print the ID of the Vlan object based on the Vlan ID in Netbox
    """
    id = list(filter(lambda x: x['vid'] == Vlanid, NetboxVlanIdsJson))

    return id[0]['id']

def NutanixGetVlanidByUuid (uuid, NetsJson):
    """ Print the Vlan ID based on the UUID of the Network in Nutanix
    """
    vid = list(filter(lambda x: x['uuid'] == uuid, NetsJson))

    return vid[0]['vlan_id']

def NetboxGetNetmaskByPrefix (IpAddr, NetboxPrefixesJson ):
    """ Print out the IP addresses network mask based on the Prefix list in Netbox
    """
    NetAddr = re.sub("\d{1,3}$","",IpAddr)
    prefs = list(filter(lambda x: re.match(NetAddr, x['prefix']), NetboxPrefixesJson))
    pref = str(prefs[len(prefs)-1]['prefix'])

    return pref.split('/')[1]

def NetboxGetClusterIdByName (FileName, NetboxClustersJson):
    """ Print the Netbox Cluster ID based on the JSON Nutanix VM file
    """
    name = str(FileName).split('.')[0]
    cluster = list(filter(lambda x: re.match(name, x['name']), NetboxClustersJson))

    return cluster[0]['id']

main()

print("END")
sys.exit(2)
