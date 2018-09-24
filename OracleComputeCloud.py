import requests
from requests_toolbelt.utils import dump
#import urllib.parse
from urlparse import urlparse
import json
from django.contrib import messages

class OracleComputeCloud():
    '''
    this class encapsulates operations that can be performed on Oracle Compute Cloud service
    '''

    # get operations

    def __init__(self, endPointUrl, authenticationDomain, cookies=None):
        '''
        Must provide an end point URL and an authentication domain
        '''

        self.__endPointUrl = endPointUrl
        self.__authenticationDomain = authenticationDomain
        self.__cookies = cookies
        self.__contentType = 'application/oracle-compute-v3+json'
        self.__accept = 'application/oracle-compute-v3+json'
        self.debug = False

        # define all resource paths
        self.resourcePaths = {
                                'ipAssociation': '/ip/association',
                                'securityApplication': '/secapplication',
                                'securityAssociation': '/secassociation',
                                'securityIPList': '/seciplist',
                                'securityList': '/seclist',
                                'securityRule': '/secrule',
                                'account': '/account',
                                'imageList': '/imagelist',
                                'machineImage': '/machineimage',
                                'orchestration': '/orchestration',
                                'instance': '/instance',
                                'shape': '/shape',
                                'SSHKey': '/sshkey',
                                'ipReservation': '/ip/reservation',
                                'storageVolume': '/storage/volume',
                                'ipNetwork': '/network/v1/ipnetwork',
                                'acl': '/network/v1/acl',
                                'ipaddressprefixset': '/network/v1/ipaddressprefixset',
                                'ipnetworkipreservation': '/network/v1/ipreservation',
                                'ipnetworkexchange': '/network/v1/ipnetworkexchange',
                                'ipsecrule': '/network/v1/secrule',
                                'secprotocol': '/network/v1/secprotocol',
                                'vnicset': '/network/v1/vnicset'
                             }

    def login(self, user, password):
        '''
        returns cookies if login is successful, None otherwise
        '''
        if (self.__cookies != None):
            return self.__cookies

        url = self.__endPointUrl + '/authenticate/'
        headerString = {'Content-Type':self.__contentType, 'Accept':self.__accept}
        fullUsername = '/Compute-' + self.__authenticationDomain + '/' + user
        authenticationString = {"password": password, "user": fullUsername}

        response = requests.post(url, json=authenticationString, headers=headerString)

        #data = dump.dump_all(response)
        #print(data.decode('utf-8'))

        if response.status_code == 204:
            self.__cookies = response.cookies
            self.__user = user
            return response.cookies

    def refresh(self, cookies=None):
        if (cookies != None):
            self.__cookies = cookies

        url = self.__endPointUrl + '/refresh/'
        headerString = {'Content-Type':self.__contentType, 'Accept':self.__accept}
        response = requests.get(url, headers=headerString, cookies=self.__cookies)

        #data = dump.dump_all(response)
        #print(data.decode('utf-8'))

        if response.status_code == 204:
            return self.__cookies

    # utility method to reboot an instance
    def updateInstances(self, instance_name, desired_state, resourceName='ALL'):
        '''
                returns json if update is successful, None otherwise
        '''

        resourcePath = self.resourcePaths['instance']
        url = self.__endPointUrl + resourcePath + instance_name

        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"desired_state": desired_state}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return response.json()
        else:
            return response.json()

    def updatesecrule(self, dst_list, secrule_name, src_list, application, action, disabled, resourceName='ALL'):
        '''
            returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['securityRule']
        url = self.__endPointUrl + resoucePath + secrule_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"dst_list": dst_list, "name": secrule_name, "src_list": src_list, "application": application, "action": action, "disabled": disabled}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateSeclist(self, policy, uri, outbound_cidr_policy, seclist_id, resourceName='ALL'):
        '''
            returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['securityList']
        url = self.__endPointUrl + resoucePath + seclist_id
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"policy": policy, "uri": uri, "outbound_cidr_policy": outbound_cidr_policy, "name": seclist_id}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updatesecip(self, secip_name, secip, description):
        resoucePath = self.resourcePaths['securityIPList']
        url = self.__endPointUrl + resoucePath + secip_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updatestring = {"secipentries": secip, "name": secip_name, "description": description}
        response = requests.put(url, json=updatestring, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateipreserve(self, parentpool, permanent, ipreserve_name, resourceName='ALL'):
        '''
            returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['ipReservation']
        url = self.__endPointUrl + resoucePath + ipreserve_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"parentpool": parentpool, "permanent": permanent, "name": ipreserve_name}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateSSHkeys(self, enabled, key, ssh_name):
        '''
                    returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['SSHKey']
        url = self.__endPointUrl + resoucePath + ssh_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"enabled": enabled, "key": key, "name": ssh_name}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updatestoragevolume(self, size, properties, tags, storage_name, description):
        '''
            returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['storageVolume']
        url = self.__endPointUrl + resoucePath + storage_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"size": size,"properties": properties, "name": storage_name, "tags": tags, "description": description}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateimage(self,default,image_name,description):
        '''
            returns json if update is successful, None otherwise
        '''

        resoucePath = self.resourcePaths['imageList']
        url = self.__endPointUrl + resoucePath + image_name
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"default": default, "description": description, "name": image_name }
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createipreserve(self, parentpool, permanent, name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipReservation']
        url = self.__endPointUrl + resoucePath + '/'
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"parentpool": parentpool, "permanent": permanent, "name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createseclist(self, policy,outbound_cidr_policy,name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['securityList']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"policy": policy, "outbound_cidr_policy": outbound_cidr_policy, "name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createsshkey(self, enabled, key, name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['SSHKey']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"enable": enabled, "key": key, "name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createsecappln(self, protocol, dport, name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['securityApplication']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"protocol": protocol, "dport": dport, "name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createseciplist(self, name, secipentries):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['securityIPList']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"secipentries": secipentries, "name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createsecrule(self, dst_list, secrule_name, src_list, secappln_name, action):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['securityRule']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"dst_list": dst_list, "name": secrule_name, "src_list": src_list, "application": secappln_name, "action": action}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createstoragevolume(self, size, properties, name,bootable, imagelist):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['storageVolume']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"size": size, "properties": properties, "name": name, "bootable": bootable,"imagelist": imagelist }
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createnonboot(self, nonbootsize, properties, nonbootable, nonbootname):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['storageVolume']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"size": nonbootsize, "properties": properties, "name": nonbootname, "bootable": nonbootable}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createorchestration(self,relationships,account,name,description,label,obj_type,ha_policy,inst_name,reverse_dns,placement_requirements,shape,instlabel,boot_order,index,volume,dataindex,datavol,sshkeys,tags,networking_seclists,nat):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['orchestration']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"relationships": relationships, "account": account, "name": name, "description": description, "oplans": [{
            "label": label, "obj_type": obj_type, "ha_policy": ha_policy, "objects": [{ "instances": [{ "name": inst_name, "reverse_dns": reverse_dns, "placement_requirements": placement_requirements, "shape": shape, "label": instlabel, "boot_order": boot_order,
            "storage_attachments": [{"index": index, "volume": volume},{"index": dataindex, "volume": datavol}], "tags": ['omcsbabsbvhnre'], "sshkeys": [sshkeys],
            "networking": {"eth0": {"seclists": [networking_seclists], "nat": nat, "dns": ['omcsbabsbvhnre']}},
            }]}]}]}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateorchestration(self,request,relationships, account, name, description, label, obj_type, ha_policy,inst_name,reverse_dns,placement_requirements,shape,imagelist,boot_order,index, volume,dataindex,datavol, sshkeys, tags,
                                                                  networking_seclists, nat):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['orchestration']
        url = self.__endPointUrl + resoucePath + name + '?action=START'
        print "Orch update url"
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"relationships": relationships, "account": account, "name": name, "description": description, "oplans": [{
            "label": label, "obj_type": obj_type, "ha_policy": ha_policy, "objects": [{ "instances": [{ "name": inst_name, "reverse_dns": reverse_dns, "placement_requirements": placement_requirements,
            "shape": shape, "label": label, "imagelist": imagelist, "boot_order": boot_order, "storage_attachments": [{"index": index, "volume": volume},{"index": dataindex, "volume": datavol}], "tags": ['omcsbabsbvhnre'], "sshkeys": [sshkeys],
            "networking": {"eth0": {"seclists": [networking_seclists], "nat": nat, "dns": ['omcsbabsbvhnre']}},
            }]}]}]}
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            messages.success(request, "Orchestration started...!!")
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createiporchestration(self,relationships,account,name,description,label,obj_type,ha_policy,inst_name,reverse_dns,placement_requirements,shape,instlabel,boot_order,index,volume,dataindex,datavol,sshkeys,tags,vnic,is_default_gateway,networking_nat,vnicsets,ipnetwork):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['orchestration']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"relationships": relationships, "account": account, "name": name, "description": description, "oplans": [{
            "label": label, "obj_type": obj_type, "ha_policy": ha_policy, "objects": [{ "instances": [{ "name": inst_name, "reverse_dns": reverse_dns, "placement_requirements": placement_requirements, "shape": shape, "label": instlabel, "boot_order": boot_order,
            "storage_attachments": [{"index": index, "volume": volume},{"index": dataindex, "volume": datavol}], "tags": [tags], "sshkeys": [sshkeys],
            "networking": {"eth0": {"vnic": vnic, "is_default_gateway": is_default_gateway, "nat": [networking_nat], "vnicsets": vnicsets, "ipnetwork": ipnetwork, "dns": ['omcsbabsbvhnre']}},
            }]}]}]}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def updateiporchestration(self,relationships, account, name, description, label, obj_type,
                                                    ha_policy,inst_name,reverse_dns,placement_requirements, shape, imagelist, boot_order,
                                                    index, volume, dataindex, datavol, sshkeys, tags,
                                                    vnic, is_default_gateway, networking_nat, vnicsets,ipnetwork):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['orchestration']
        url = self.__endPointUrl + resoucePath + name + '?action=START'
        print "Orch update url"
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        updateString = {"relationships": relationships, "account": account, "name": name, "description": description, "oplans": [{
            "label": label, "obj_type": obj_type, "ha_policy": ha_policy, "objects": [{ "instances": [{ "name": inst_name, "reverse_dns": reverse_dns, "placement_requirements": placement_requirements,
            "shape": shape, "label": label, "imagelist": imagelist, "boot_order": boot_order, "storage_attachments": [{"index": index, "volume": volume},{"index": dataindex, "volume": datavol}], "tags": ['omcsbabsbvhnre'], "sshkeys": [sshkeys],
            "networking": {"eth0": {"vnic": vnic, "is_default_gateway": is_default_gateway, "nat": [networking_nat], "vnicsets": vnicsets, "ipnetwork": ipnetwork, "dns": ['omcsbabsbvhnre']}},
            }]}]}]
        }
        response = requests.put(url, json=updateString, headers=headerString, cookies=self.__cookies)
        print response

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createipnetwork(self,name,ipAdressPrefix,ipNetworkExchange):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipNetwork']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "ipAdressPrefix": ipAdressPrefix, "ipNetworkExchange": ipNetworkExchange}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createacl(self, name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['acl']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createipaddressprefixset(self, name, ipAddressPrefixes):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipaddressprefixset']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "ipAddressPrefixes": ipAddressPrefixes}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createipnetworkipreservation(self, name, ipAddressPool):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipnetworkipreservation']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "ipAddressPool": ipAddressPool}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createipnetworkexchange(self, name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipnetworkexchange']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createprefixdestinatiosecrule(self, name,flowdirection,acl,secProtocols,dstIpAddressPrefixSets):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipsecrule']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "flowDirection": flowdirection, "acl": acl, "secProtocols": [secProtocols], "dstIpAddressPrefixSets": [dstIpAddressPrefixSets]}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createprefixsoucesecrule(self, name,flowdirection,acl,secProtocols,srcipaddressprefixSets):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipsecrule']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "flowDirection": flowdirection, "acl": acl, "secProtocols": [secProtocols],"srcipaddressprefixSets": [srcipaddressprefixSets]}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createsecprotocol(self, description,ipProtocol,dstPortSet,name):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['secprotocol']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"description": description, "ipProtocol": ipProtocol, "dstPortSet": dstPortSet,"name": name}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def createvnicset(self, name,vnics,appliedAcls):
        '''
            returns json if creation is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['vnicset']
        url = self.__endPointUrl + resoucePath + '/'
        print url
        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        createString = {"name": name, "vnics": vnics, "appliedAcls": appliedAcls}
        response = requests.post(url, json=createString, headers=headerString, cookies=self.__cookies)
        print response

        # self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def deleteipreserve(self, name):
        '''
            returns json if update is successful, None otherwise
        '''
        resoucePath = self.resourcePaths['ipReservation']
        url = self.__endPointUrl + resoucePath + name
        response = requests.delete(url, cookies=self.__cookies)

        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def buildContainerUri(self, isPublic=None, user=None):
        container = '/Compute-' + self.__authenticationDomain
        if isPublic == True:
            return  '/oracle/public'

        if user == None:
            return container #+ '/' + self.__user
        #else:
            #return container #+ '/' + user

    # utility methods
    def getResources(self, resourcePath, container, resourceName='ALL', queryParams=None):
        url = self.__endPointUrl + resourcePath

        if resourceName == 'ALL':
            url = url + container
            if not url.endswith('/'):
                url += '/'
            # if queryParams != None and type(queryParams) is dict:
            #     url += '?' + urllib.parse.urlencode(queryParams)
            # if url.endswith('?'):
            #     url = url[:-1]

        elif resourceName.startswith('/'):
            url = url + resourceName
        else:
            url = url + '/' + resourceName
        print url
        headerString = {'Content-Type':self.__contentType, 'Accept':self.__accept}
        response = requests.get(url, headers=headerString, cookies=self.__cookies)

        self.debugLog(response)

        if response.status_code == 200:
            print "---status 200----"
            jsonResponse = response.json()
            return (jsonResponse['result'] if resourceName=='ALL' else jsonResponse)
            #return jsonResponse
        elif response.status_code == 404:
            return []
        else:
            return response.json()
        #else:
        #    raise OCCException('Response code: ' + str(response.status_code) + ', ' + str(response.content))

    def getIpnetwork(self, ipnetworkName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipNetwork']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipnetworkName, queryParams)

    def getIpexchange(self, ipnexchangeName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipnetworkexchange']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipnexchangeName, queryParams)

    def getVNICsets(self, vnicName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['vnicset']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, vnicName, queryParams)

    def getIPsecrule(self, ipsecruleName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipsecrule']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipsecruleName, queryParams)

    def getACL(self, ACLName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['acl']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ACLName, queryParams)

    def getSecurityProtocols(self, SecProtocolName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['secprotocol']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, SecProtocolName, queryParams)

    def getIpAddrprefixsets(self, PrefixSetName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipaddressprefixset']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, PrefixSetName, queryParams)

    def getIPnetworkReservations(self, ipnetworkReservationName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipnetworkipreservation']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipnetworkReservationName, queryParams)

    def getIPReservations(self, ipReservationName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipReservation']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipReservationName, queryParams)


    def getIPAssociations(self, ipAssociationName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['ipAssociation']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, ipAssociationName, queryParams)

    def getOrchestrations(self, orchestrationName='ALL', user=None, status=None):
        resourcePath = self.resourcePaths['orchestration']
        container = self.buildContainerUri(user=user) #Compute-omcsservicedom1
        queryParams = {}
        if status != None:
            queryParams = {"status": status}

        return self.getResources(resourcePath, container, orchestrationName, queryParams)

    def getOrchV1(self, user=None, status=None):
        resourcePath = self.resourcePaths['orchestration']
        container = self.buildContainerUri(user=user) #Compute-omcsservicedom1
        url = self.__endPointUrl + resourcePath + container + '/orchestration/'
        print url

        s = requests.Session()

        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        #response = requests.get(url, headers=headerString, cookies=self.__cookies)
        response = s.get(url, headers=headerString, cookies=self.__cookies)
        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse['result']
        elif response.status_code == 404:
            return []
        else:
            return response.json()

    def getOrchV2(self, user=None, status=None):
        #resourcePath = self.resourcePaths['orchestration']
        container = self.buildContainerUri(user=user) #Compute-omcsservicedom1
        url = self.__endPointUrl + '/platform/v1/orchestration' + container + '/orchestration/'
        print url

        s = requests.Session()

        headerString = {'Content-Type': self.__contentType, 'Accept': self.__accept}
        #response = requests.get(url, headers=headerString, cookies=self.__cookies)
        response = s.get(url, headers=headerString, cookies=self.__cookies)
        self.debugLog(response)

        if response.status_code == 200:
            jsonResponse = response.json()
            return jsonResponse['result']
        elif response.status_code == 404:
            return []
        else:
            return response.json()


    def getSecurityApplications(self, securityApplicationName='ALL',  user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityApplication']
        container = self.buildContainerUri( user=user)
        return self.getResources(resourcePath, container, securityApplicationName, queryParams)

    def getSecurityApplications1(self, securityApplicationName='ALL', isPublic=True, user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityApplication']
        container = self.buildContainerUri(isPublic, user)
        return self.getResources(resourcePath, container, securityApplicationName, queryParams)

    def getSecurityAssociations(self, securityAssociationName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityAssociation']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, securityAssociationName, queryParams)

    def getSecurityIPLists(self, securityIPListName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityIPList']
        container = self.buildContainerUri( user=user)
        return self.getResources(resourcePath, container, securityIPListName, queryParams)

    def getSecurityIPLists1(self, securityIPListName='ALL', isPublic=True, user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityIPList']
        container = self.buildContainerUri(isPublic, user=user)
        return self.getResources(resourcePath, container, securityIPListName, queryParams)

    def getSecurityLists(self, securityListName='ALL', user=None):
        resourcePath = self.resourcePaths['securityList']
        container = self.buildContainerUri(user)
        return self.getResources(resourcePath, container, securityListName)

    def getSecurityRules(self, securityRuleName='ALL', user=None, queryParams=None):
        resourcePath = self.resourcePaths['securityRule']
        container = self.buildContainerUri(user)
        return self.getResources(resourcePath, container, securityRuleName, queryParams)

    def getAccounts(self, accountName='ALL'):
        resourcePath = self.resourcePaths['account']
        container = '/Compute-' + self.__authenticationDomain
        return self.getResources(resourcePath, container, accountName)

    def getImageLists(self, imageListName='ALL', isPublic=True, user=None):
        '''
        if imageListName == 'ALL'
            returns a list of dictionaries of image list details
        else
            returns a dictionary

        '''
        resourcePath = self.resourcePaths['imageList']
        container = self.buildContainerUri(user)
        return self.getResources(resourcePath, container, imageListName)

    def getMachineImages(self, machineImageName='ALL', isPublic=True, user=None):
        resourcePath = self.resourcePaths['machineImage']
        container = self.buildContainerUri(isPublic, user)
        return self.getResources(resourcePath, container, machineImageName)

    def getInstances(self, instanceName='ALL', user=None):
        '''
        if instanceName == 'ALL'
            returns a list of dictionaries of instance details
        else
            returns a dictionary
        '''
        resourcePath = self.resourcePaths['instance']
        container = self.buildContainerUri(user=user)
        return self.getResources(resourcePath, container, instanceName)

    def getShapes(self, shapeName='ALL'):
        '''
        if shapeName == None:
            return a list of dictionaries of all shapes, each of which contains a set of shape information
        else
            return a dictionaries of the named shape

        sample returns
        [{"nds_iops_limit": 0, "ram": 7680, "cpus": 2.0, "root_disk_size": 0, "uri": "https://api-z24.compute.us6.oraclecloud.com/shape/oc3", "io": 200, "name": "oc3"},
         {"nds_iops_limit": 0, "ram": 15360, "cpus": 2.0, "root_disk_size": 0, "uri": "https://api-z24.compute.us6.oraclecloud.com/shape/oc1m", "io": 200, "name": "oc1m"}]
        '''

        resourcePath = self.resourcePaths['shape']
        container = ''
        return self.getResources(resourcePath, container, shapeName)

    def getSSHKeys(self, sshKeyName='ALL', user=None):
        resourcePath = self.resourcePaths['SSHKey']
        container = self.buildContainerUri(user)
        return self.getResources(resourcePath, container, sshKeyName)



    def getStorageVolumes(self, storageVolumeName='ALL', user=None):
        resourcePath = self.resourcePaths['storageVolume']
        container = self.buildContainerUri(user)
        return self.getResources(resourcePath, container, storageVolumeName)

    '''
    utility operations
    '''
    def buildResourceName(self, simpleName):
        if not simpleName.startswith('/'):
            return "/Compute-" + self.__authenticationDomain + '/' + self.__user + '/' + simpleName
        else:
            return  "/Compute-" + self.__authenticationDomain + '/' + self.__user + simpleName

    def debugLog(self, response):
        # debug
        if self.debug:
            data = dump.dump_all(response)
            print(data.decode('utf-8'))


class OCCException(Exception):
    pass
    #return render_to_response('invalid.html')

