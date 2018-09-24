from django.shortcuts import render, render_to_response,redirect
from app.OracleComputeCloud import OracleComputeCloud
from django.views.decorators.csrf import csrf_exempt,csrf_protect,ensure_csrf_cookie
from django.contrib import messages
from app.models import Idd_data,Shapes,Document,Image,SSHkeys,Tier,Instance,Domain,Inventory\
    ,Instances,Ipreservation,Api,Customer,SecRule,Secip,Seclist,SecApp,StorageVolume,Auth,Orchestration,\
    Ipnetwork, IpNetworkExchange, VNICsets, IPSecRule, ACLs, SecProtocols, IpAddrPrefixSets, Ipreservation,Ipnetworkreservation,IpAssociation
from app.forms import DocumentForm
from app import authenticate_oscs
#from Crypto.PublicKey import RSA
import MySQLdb, xlrd,os,csv,shutil
from django.db.models import Count,Sum,Q
import re,requests,json
from django.http import HttpResponse
# Create your views here.


def dictfetchall(cursor):
    "Returns all rows from a cursor as a dict"
    desc = cursor.description
    return [
        dict(zip([col[0] for col in desc], row))
        for row in cursor.fetchall()
        ]

def listfetchall(val):
    "Returns a value using list data purification"
    q = str(val).strip('[]')  # extract non-null values from database
    r = str(q).strip('()')
    s = r[:-1]  # Data purification
    t = s[1:]
    u = t[:-1]
    return u[1:]

def logout(request):
    user = request.session['username']
    Image.objects.filter(user=user).delete()
    SSHkeys.objects.filter(user=user).delete()
    Shapes.objects.filter(user=user).delete()
    Document.objects.filter(user=user).delete()
    Instances.objects.filter(user=user).delete()
    SecRule.objects.filter(user=user).delete()
    Secip.objects.filter(user=user).delete()
    Seclist.objects.filter(user=user).delete()
    SecApp.objects.filter(user=user).delete()
    StorageVolume.objects.filter(user=user).delete()
    IpAssociation.objects.filter(user=user).delete()
    Orchestration.objects.filter(user=user).delete()
    Ipnetwork.objects.filter(user=user).delete()
    IpNetworkExchange.objects.filter(user=user).delete()
    VNICsets.objects.filter(user=user).delete()
    IPSecRule.objects.filter(user=user).delete()
    ACLs.objects.filter(user=user).delete()
    SecProtocols.objects.filter(user=user).delete()
    IpAddrPrefixSets.objects.filter(user=user).delete()
    Ipreservation.objects.filter(user=user).delete()
    Ipnetworkreservation.objects.filter(user=user).delete()
    Auth.objects.filter(user=user).delete()
    Domain.objects.all().delete()
    connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
    cursord = connection.cursor()
    # #cursord.execute("delete from account where user like %s",(request.session.get('username'),))
    # cursord.execute("delete from image where user like %s",(request.session.get('username'),))
    # cursord.execute("delete from sshkeys where user like %s",(request.session.get('username'),))
    # cursord.execute("delete from shape where user like %s",(request.session.get('username'),))
    cursord.execute("delete from django_session")
    # cursord.execute("delete from dom")
    # cursord.execute("delete from app_document where user like %s", (request.session.get('username'),))
    #
    # #request.session.flush()
    connection.commit()
    cursord.close()

    # try:
    #     del request.session['username']
    #
    #   #del request.session['password']
    # except:
    #     pass
    print request.session.get('username')
    return render_to_response('logout.html')

def cap_var(request):
    idds = request.POST.get('idd')  # Collecting the input values from the front end
    zone = request.POST.get('zone')

    if idds == None:                # checking IDD is None in the case of page refresh
        idds = "fonzi"              # Indicating IDD with NULL notation
    Domain.objects.create(dom=idds,zone=zone) # Loading IDD to the Domain table of Database

    if idds == "fonzi":             # whether IDD is NULL
        p = list(Domain.objects.values_list('dom').exclude(dom__contains="fonzi"))
        q = str(p).strip('[]')      # extract non-null values from database
        r = str(q).strip('()')
        s = r[:-1]                  # Data purification
        t = s[1:]
        u = t[:-1]
        idds = u[1:]
        p = list(Domain.objects.values_list('zone').exclude(dom__contains="fonzi"))
        q = str(p).strip('[]')  # extract non-null values from database
        r = str(q).strip('()')
        s = r[:-1]  # Data purification
        t = s[1:]
        u = t[:-1]
        zone = u[1:]
    print "input zone" + zone

    #idd ='omcsops'
    p = list(Idd_data.objects.values_list('idd').distinct().filter(idd__contains=idds)) # Collecting authDomain from IDD
    q = str(p).strip('[]')
    r = str(q).strip('()')          # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    authDomain = u[1:]
    print "authdomain "+authDomain

    p = list(Idd_data.objects.values_list('api_id_id').distinct().filter(zone__contains=zone)) # Collecting api from authDomain
    q = str(p).strip('[]')
    r = str(q).strip('()')          # Data purification
    s = r[:-1]
    t = s[:-1]
    api_id_id = t
    print api_id_id

    p = list(Api.objects.values_list('api').distinct().filter(id__in=api_id_id))  # Collecting authDomain from IDD
    q = str(p).strip('[]')
    r = str(q).strip('()')  # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    url = u[1:]
    print "api "+url

    p = list(Idd_data.objects.values_list('customer_id_id').distinct().filter(idd__contains=authDomain))  # Collecting api from authDomain
    q = str(p).strip('[]')
    r = str(q).strip('()')  # Data purification
    s = r[:-1]
    t = s[:-1]
    customer_id_id = t

    p = list(Customer.objects.values_list('customer').distinct().filter(id__in=customer_id_id))  # Collecting authDomain from IDD
    q = str(p).strip('[]')
    r = str(q).strip('()')  # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    customer = u[1:]

    p = list(Idd_data.objects.values_list('storage').distinct().filter(idd__contains=authDomain))  # Collecting api from authDomain
    q = str(p).strip('[]')
    r = str(q).strip('()')  # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    storage = u[1:]

    p = list(Idd_data.objects.values_list('dccode').distinct().filter(idd__contains=authDomain))  # Collecting dccode from authDomain
    q = str(p).strip('[]')
    r = str(q).strip('()')          # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    dccode = u[1:]

    p = list(Idd_data.objects.values_list('custcode').distinct().filter(idd__contains=authDomain))    # Collecting custcode from authDomain
    q = str(p).strip('[]')
    r = str(q).strip('()')          # Data purification
    s = r[:-1]
    t = s[1:]
    u = t[:-1]
    custcode = u[1:]

    account = '/Compute-%s' % (authDomain)  # account name from authDomain
    #account = Account.objects.values_list('name').filter(name__contains=acc)

    return (authDomain,api_id_id,url,customer_id_id,customer,storage,dccode,custcode, account,zone)


@ensure_csrf_cookie
@csrf_exempt
def ansviews(request, template_name='mypage.html'):
    """ Function for front end views of ansible UI webpage,
    Firstly it perform user authentication for valid users.
    Next it take the file input from user & validate the file content & Display it in the UI
    So that it can be used to submitted to build VM """

    if request.method == "POST" :   # checking POST request
        (authDomain, api_id_id, url, customer_id_id, customer, storage, dccode, custcode, account,zone) = cap_var(request)

        username = request.POST.get('username', '')     # get the input from front end text box
        password = request.POST.get('password', '')
        #zone = request.POST.get('zone', '')
        occ = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
        cookies = occ.login(user=username, password=password)  # Collecting the cookies from OCC Login
        custname = authDomain.upper()


        if request.session.get('username') == None: # checking username is NULL

            if cookies == None or authDomain == None or url == None:    # checking either cookies, i/p is NULL
                return render_to_response('invalid.html') # redirect to invalid page
            else:
                tabimg = occ.getImageLists()  # Collecting the Image,SSH,Shape data from OCC(REST API)
                tabssh = occ.getSSHKeys()
                tabshape = occ.getShapes()
                tabinst = occ.getInstances()
                tabsecrule = occ.getSecurityRules()
                tabsecip = occ.getSecurityIPLists()
                tabsecippub = occ.getSecurityIPLists1()
                tabseclist = occ.getSecurityLists()
                tabsecapp = occ.getSecurityApplications()
                tabsecapppub = occ.getSecurityApplications1()
                tabstoragevol = occ.getStorageVolumes()
                tabipreserve = occ.getIPReservations()
                tabipasso = occ.getIPAssociations()
                # tab11 = occ.getOrchestrations()
                tabv1 = occ.getOrchV1()
                tabv2 = occ.getOrchV2()

                tabipnetwork = occ.getIpnetwork()
                tabipexhng = occ.getIpexchange()
                tabvnic = occ.getVNICsets()
                tabipsecrule = occ.getIPsecrule()
                tabacl = occ.getACL()
                tabsecprotocol = occ.getSecurityProtocols()
                tabipaddrprefixsets = occ.getIpAddrprefixsets()
                tabipnetworkreserve = occ.getIPnetworkReservations()

                # Gather image
                image = tabv1[0]['oplans'][0]['objects'][0]['instances'][0]['imagelist']


                # Define Shape conversions
                shape_to_cpu = dict(oc4m=8, oc7=16, oc3m=4, oc5m=16, oc3=1, oc5=4, oc4=2, oc1m=1, oc2m=2, oc6=8)

                # Gather OCPU Totals Information
                shapelist = []
                for item in tabinst:
                    if item['shape'] in shape_to_cpu.keys():
                        shapelist.append(shape_to_cpu[(item['shape'])])

                total_cpu_used = sum(shapelist)
                print "------- total cpu ------"
                print total_cpu_used

                # publiclist = []
                # for item in tab9pub:
                #     publiclist.append(item)
                #
                # total_public_secappln = sum(publiclist)
                print "------ total public secappln-------"
                # print total_public_secappln
                public=len(tabsecapppub)

                volume_size_list = []
                for item in tabstoragevol:
                    volume_size_list.append(float(item['size']))

                total_volume_size = sum(volume_size_list)
                total_block_storage_used_tb = total_volume_size / 1024.0 / 1024.0 / 1024.0 / 1024.0

                print "----- total volume -----"
                print total_block_storage_used_tb

                apipattern = re.match('https://.*compute.(.*).oraclecloud', url)
                location = apipattern.group(1)
                print "----location----"
                print location

                request.session['username'] = username  # getting current User
                user = request.session['username']

                Auth.objects.create(username=username, password=password, user=user)

                valimg = map(lambda x: (x['name'], x['default'], x['description'],x['entries'][0]['machineimages'][0], x['uri']),
                             tabimg)  # Data purification through 'lamba' expression
                valssh = map(lambda x: (x['name'], x['key'], x['uri'], x['enabled']), tabssh)
                valshape = map(lambda x: (x['name'], x['ram'], x['uri'], x['cpus'], x['io'], x['nds_iops_limit']),
                               tabshape)
                valinst = map(
                    lambda x: (x['name'], x['ip'], x['state'], x['label'], x['platform'], x['shape'], x['imagelist'],
                               x['attributes']['network']['nimbula_vcable-eth0']['id'], x['domain'],
                               x['placement_requirements'], x['site']
                               , x['sshkeys'], x['attributes']['dns']['hostname'], x['networking']['eth0']['seclists'], x['hostname'],
                               x['quota_reservation'], x['disk_attach']
                               , x['priority'], x['state'], x['vnc'], x['storage_attachments'], x['quota'],
                               x['fingerprint'], x['error_reason']
                               , x['vcable_id'], x['uri'], x['reverse_dns'], x['entry'], x['boot_order']), tabinst)

                valsecrule = map(
                    lambda x: (x['name'], x['application'], x['src_list'], x['dst_list'], x['action'], x['disabled']),
                    tabsecrule)
                valsecip = map(lambda x: (x['name'], x['secipentries']), tabsecip)
                valsecippub = map(lambda x: (x['name'], x['secipentries']), tabsecippub)
                valseclist = map(lambda x: (x['name'], x['account'], x['outbound_cidr_policy'], x['policy']),
                                 tabseclist)
                valsecapp = map(lambda x: (x['name'], x['protocol'], x['dport']), tabsecapp)
                valsecapppub = map(lambda x: (x['name'], x['protocol'], x['dport']), tabsecapppub)
                valstoragevol = map(lambda x: (
                x['name'], x['properties'], x['tags'], x['status'], x['status_timestamp'], x['shared'], x['size']),
                                    tabstoragevol)
                valipasso = map(lambda x: (x['account'], x['vcable'], x['name'], x['ip'], x['uri'], x['parentpool'], x['reservation']), tabipasso)
                valv1 = map(lambda x: (x['name'], x['status'], x['description'], x['uri'],
                                       x['oplans'][0]['objects'][0]['instances'][0]['networking']['eth0']['seclists'][0],
                                       x['oplans'][0]['objects'][0]['instances'][0]['networking']['eth0']['nat'],
                                       x['oplans'][0]['objects'][0]['instances'][0]['name'], x['oplans'][0]['objects'][0]['instances'][0]['ip'],
                                       x['oplans'][0]['objects'][0]['instances'][0]['shape'], x['oplans'][0]['objects'][0]['instances'][0]['state'],
                                       x['oplans'][0]['objects'][0]['instances'][0]['storage_attachments'][0]['volume'],
                                       x['oplans'][0]['objects'][0]['instances'][0]['sshkeys'][0],
                                       x['oplans'][0]['objects'][0]['instances'][0]['label']), tabv1)
                valv2 = map(lambda x: (x['name'], x['status'], x['description'], x['uri'],
                                       x['objects'][0]['health']['object']['networking']['eth0']['seclists'],
                                       x['objects'][0]['health']['object']['networking']['eth0']['nat'],
                                       x['objects'][0]['name'], x['objects'][0]['health']['object']['ip'], x['objects'][0]['health']['object']['shape'],
                                       x['objects'][0]['health']['object']['state'], x['objects'][0]['health']['object']['storage_attachments'][0]['volume'],
                                       x['objects'][0]['health']['object']['sshkeys'][0],x['objects'][0]['template']['label']), tabv2)

                valipnetwork = map(lambda x: (
                x['name'], x['uri'], x['description'], x['tags'], x['ipAddressPrefix'], x['ipNetworkExchange'],
                x['publicNaptEnabledFlag']), tabipnetwork)
                valipexchng = map(lambda x: (x['name'], x['uri'], x['description'], x['tags']), tabipexhng)
                valvnic = map(
                    lambda x: (x['name'], x['uri'], x['description'], x['tags'], x['vnics'], x['appliedAcls']), tabvnic)
                valipsecrule = map(lambda x: (
                    x['name'], x['uri'], x['description'], x['tags'], x['acl'], x['flowDirection'], x['srcVnicSet'],
                    x['dstVnicSet'], x['srcIpAddressPrefixSets'], x['dstIpAddressPrefixSets'], x['secProtocols'],
                    x['enabledFlag']), tabipsecrule)
                valacl = map(lambda x: (x['name'], x['uri'], x['description'], x['tags'], x['enabledFlag']), tabacl)
                valsecprotocol = map(lambda x: (
                x['name'], x['uri'], x['description'], x['tags'], x['ipProtocol'], x['srcPortSet'], x['dstPortSet']),
                                     tabsecprotocol)
                valaddrprefixsets = map(
                    lambda x: (x['name'], x['uri'], x['description'], x['tags'], x['ipAddressPrefixes']),
                    tabipaddrprefixsets)
                valipreserve = map(lambda x: (
                x['ip'], x['name'], x['account'], x['used'], x['tags'], x['uri'], x['parentpool'], x['permanent']),
                                   tabipreserve)
                valipnetworkreserve = map(
                    lambda x: (x['name'], x['uri'], x['description'], x['tags'], x['ipAddress'], x['ipAddressPool']),
                    tabipnetworkreserve)

                for name, default, description, machineimages, uri in valimg:  # loading data to the respective tables of the database
                    Image.objects.create(image_name=name, deflt=default, description=description, machineimages=machineimages, uri=uri,
                                         location=location, total_block_storage_used=total_block_storage_used_tb,
                                             total_cpu_used=total_cpu_used,user=user,
                                         api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, key, uri, enabled in valssh:
                    SSHkeys.objects.create(ssh_name=name, key=key, uri=uri, enabled=enabled, user=user,
                                           api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, ram, uri, cpus, io, nds_iops_limit in valshape:
                    Shapes.objects.create(shape_name=name, ram=ram, uri=uri, cpus=cpus, io=io,
                                          nds_iops_limit=nds_iops_limit, user=user, api_id_id=api_id_id,
                                          customer_id_id=customer_id_id)
                for name, ip, state, label, platform, shape, imagelist, attributes_id, domain, placement_requirements, site, sshkeys, dns_custname, networking_seclist, custname, quota_reservation, disk_attach, priority, state, vnc, storage_name, quota, fingerprint, error_reason, vcable_id, uri, reverse_dns, entry, boot_order in valinst:
                    Instances.objects.create(inst_name=name, private_ip=ip, inst_state=state, label=label, platform=platform,
                                             shape=shape, imagelist=imagelist, attributes_id=attributes_id,
                                             inst_domain=domain, placement_requirements=placement_requirements,
                                             site=site, sshkeys=sshkeys, dns_hostname=dns_custname,networking_seclist=networking_seclist, hostname=custname,
                                             quota_reservation=quota_reservation, disk_attach=disk_attach,
                                             priority=priority, state=state, vnc=vnc, storage_name=storage_name,
                                             quota=quota, fingerprint=fingerprint, error_reason=error_reason,
                                             vcable_id=vcable_id, uri=uri, reverse_dns=reverse_dns, entry=entry, boot_order=boot_order,
                                             location=location, total_block_storage_used=total_block_storage_used_tb,
                                             total_cpu_used=total_cpu_used, user=user, api_id_id=api_id_id,
                                             customer_id_id=customer_id_id)

                for name, application, src_list, dst_list, action, disabled in valsecrule:
                    SecRule.objects.create(name=name, application=application, src_list=src_list, dst_list=dst_list,
                                           action=action, disabled=disabled, user=user, api_id_id=api_id_id,
                                           customer_id_id=customer_id_id)
                for name, secipentries in valsecip:
                    Secip.objects.create(name=name, secipentries=secipentries, user=user, api_id_id=api_id_id,
                                         customer_id_id=customer_id_id)
                for name, secipentries in valsecippub:
                    Secip.objects.create(name=name, secipentries=secipentries, user=user, api_id_id=api_id_id,
                                         customer_id_id=customer_id_id)
                for name, account, outbound, policy in valseclist:
                    Seclist.objects.create(name=name, account=account, outbound_cidr_policy=outbound, policy=policy,
                                           user=user, api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, protocol, dport in valsecapp:
                    SecApp.objects.create(name=name, protocol=protocol, dport=dport,public=public, user=user, api_id_id=api_id_id,
                                          customer_id_id=customer_id_id)
                for name, protocol, dport in valsecapppub:
                    SecApp.objects.create(name=name, protocol=protocol, dport=dport, user=user, api_id_id=api_id_id,
                                          customer_id_id=customer_id_id)
                for name, properties, tags, status, status_timestamp, shared, size in valstoragevol:
                    StorageVolume.objects.create(name=name, properties=properties, tags=tags, status=status,
                                                 status_timestamp=status_timestamp, shared=shared, size=size, location=location,
                                                 total_block_storage_used=total_block_storage_used_tb,
                                                 total_cpu_used=total_cpu_used, user=user,
                                                 api_id_id=api_id_id, customer_id_id=customer_id_id)
                for account,vcable,name,ip,uri,parentpool,reservation in valipasso:
                    IpAssociation.objects.create(account=account,vcable=vcable,name=name,ip=ip,parentpool=parentpool,reservation=reservation,user=user,
                                                 api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, status, description, uri,inst_seclist,ipreserve,inst_name, private_ip, state, inst_shape, storage, ssh_name, inst_label in valv1:
                    Orchestration.objects.create(name=name, status=status, description=description, uri=uri,
                                                 inst_seclist=inst_seclist,ipreserve=ipreserve,inst_name=inst_name, private_ip=private_ip,
                                                 inst_shape=inst_shape, storage=storage, ssh_name=ssh_name,
                                                 inst_label=inst_label,imagelist=image, location=location,
                                                 total_block_storage_used=total_block_storage_used_tb,
                                                 total_cpu_used=total_cpu_used,user=user,
                                                 api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, status, description, uri,inst_seclist,ipreserve,inst_name, private_ip, state, inst_shape, storage, ssh_name, inst_label in valv2:
                    Orchestration.objects.create(name=name, status=status, description=description, uri=uri,
                                                 inst_seclist=inst_seclist,ipreserve=ipreserve, inst_name=inst_name, private_ip=private_ip,
                                                 inst_shape=inst_shape, storage=storage, ssh_name=ssh_name,
                                                 inst_label=inst_label, imagelist=image, location=location,
                                                 total_block_storage_used=total_block_storage_used_tb,
                                                 total_cpu_used=total_cpu_used, user=user,
                                                 api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, uri, description, tags, ipAddressPrefix, ipNetworkExchange, publicNaptEnabledFlag in valipnetwork:
                    Ipnetwork.objects.create(name=name, uri=uri, description=description, tags=tags,
                                             ipAddressPrefix=ipAddressPrefix, ipNetworkExchange=ipNetworkExchange,
                                             publicNaptEnabledFlag=publicNaptEnabledFlag, user=user,
                                             api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, uri, description, tags in valipexchng:
                    IpNetworkExchange.objects.create(name=name, uri=uri, description=description, tags=tags, user=user,
                                                     api_id_id=api_id_id, customer_id_id=customer_id_id)
                # for name, uri, description, tags, vnics, appliedAcls in valvnic:
                #     VNICsets.objects.create(name=name, uri=uri, description=description, tags=tags, vnics=vnics,
                #                             appliedAcls=appliedAcls, user=user, api_id_id=api_id_id,
                #                             customer_id_id=customer_id_id)
                for name, uri, description, tags, acl, flowDirection, srcVnicSet, dstVnicSet, srcIpAddressPrefixSets, dstIpAddressPrefixSets, secProtocols, enabledFlag in valipsecrule:
                    IPSecRule.objects.create(name=name, uri=uri, description=description, tags=tags, acl=acl,
                                             flowdirection=flowDirection, srcVnicSet=srcVnicSet, dstVnicSet=dstVnicSet,
                                             srcIpAddressPrefixSets=srcIpAddressPrefixSets,
                                             dstIpAddressPrefixSets=dstIpAddressPrefixSets, secProtocols=secProtocols,
                                             enabledFlag=enabledFlag, user=user, api_id_id=api_id_id,
                                             customer_id_id=customer_id_id)
                for name, uri, description, tags, enabledFlag in valacl:
                    ACLs.objects.create(name=name, uri=uri, description=description, tags=tags, enabledFlag=enabledFlag,
                                        user=user, api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, uri, description, tags, ipProtocol, srcPortSet, dstPortSet in valsecprotocol:
                    SecProtocols.objects.create(name=name, uri=uri, description=description, tags=tags,
                                                ipProtocol=ipProtocol, srcPortSet=srcPortSet, dstPortSet=dstPortSet,
                                                user=user, api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, uri, description, tags, ipAddressPrefixes in valaddrprefixsets:
                    IpAddrPrefixSets.objects.create(name=name, uri=uri, description=description, tags=tags,ipAddressPrefixes=ipAddressPrefixes,user=user, api_id_id=api_id_id, customer_id_id=customer_id_id)
                for ip, name, account, used, tags, uri, parentpool, permanent in valipreserve:
                    Ipreservation.objects.create(public_ip=ip, name=name, account=account, used=used, tags=tags,
                                                 uri=uri, parentpool=parentpool, permanent=permanent, user=user,
                                                 api_id_id=api_id_id, customer_id_id=customer_id_id)
                for name, uri, description, tags, ipAddress, ipAddressPool in valipnetworkreserve:
                    Ipnetworkreservation.objects.create(name=name, uri=uri, description=description, tags=tags,
                                                        ipAddress=ipAddress, ipAddressPool=ipAddressPool,
                                                        user=user, api_id_id=api_id_id, customer_id_id=customer_id_id)
        inventory = Inventory.objects.all()
        instances = Instances.objects.all()
        secrule = SecRule.objects.all()
        seclists = Seclist.objects.all()
        secapp = SecApp.objects.all()
        secip = Secip.objects.all()
        ipnetworks = Ipnetwork.objects.all()
        ipexchanges = IpNetworkExchange.objects.all()
        VNICset = VNICsets.objects.all()
        ipsecrule = IPSecRule.objects.all()
        acls = ACLs.objects.all()
        secprotocol = SecProtocols.objects.all()
        ipaddrprefixset = IpAddrPrefixSets.objects.all()
        ipnetworkreserve = Ipnetworkreservation.objects.all()
        sshkey = SSHkeys.objects.all()
        storagevolume = StorageVolume.objects.all()
        orchestration = Orchestration.objects.all()
        images = Image.objects.all()

        instname = Instances.objects.all().values('inst_name').count()
        cpu = list(Instances.objects.all().values('total_cpu_used').distinct())
        ocpu = int(cpu[0]['total_cpu_used'])
        secrulename = SecRule.objects.all().values('name').count()
        secruleenable = SecRule.objects.values_list('disabled').filter(disabled='False').count()
        seclistname = Seclist.objects.all().values('name').count()
        seclistused = Seclist.objects.values_list('outbound_cidr_policy').filter(
            outbound_cidr_policy='PERMIT').count()
        secapplnname = SecApp.objects.all().values('name').count()
        secapppublic = SecApp.objects.all().values('public').distinct()
        secipname = Secip.objects.all().values('name').count()
        secippublic = Secip.objects.values_list('name').filter(name__contains='oracle/public').count()
        ipreservename = Ipreservation.objects.all().values('name').count()
        ipreserveused = Ipreservation.objects.values_list('used').filter(used='True').count()
        ipnetworkname = Ipnetwork.objects.all().values('name').count()
        ipexchngname = IpNetworkExchange.objects.all().values('name').count()
        vnicsets = VNICsets.objects.all().values('name').count()
        ipsecrulename = IPSecRule.objects.all().values('name').count()
        ipsecruleenable = IPSecRule.objects.all().values_list('enabledFlag').filter(enabledFlag='True').count()
        aclname = ACLs.objects.all().values('name').count()
        aclenable = ACLs.objects.all().values_list('enabledFlag').filter(enabledFlag='True').count()
        secprotocolname = SecProtocols.objects.all().values('name').count()
        ipaddrprefixsetname = IpAddrPrefixSets.objects.all().values('name').count()
        ipnetworkreservename = Ipnetworkreservation.objects.all().values('name').count()

        sshname = SSHkeys.objects.all().values('ssh_name').count()
        sshenabled = SSHkeys.objects.values_list('enabled').filter(enabled='True').count()

        volname = StorageVolume.objects.all().values('name').count()
        volsizes = StorageVolume.objects.aggregate(vol_size=Sum('size'))
        volsize = volsizes['vol_size'] / (1024.0 * 1024.0 * 1024.0 * 1024.0)

        orchname = Orchestration.objects.all().values('name').count()
        orchstatus = Orchestration.objects.values_list('status').filter(
            Q(status='ready') | Q(status='active')).count()

        imgname = Image.objects.all().values('image_name').count()

        if secipname > 99:
            messages.warning(request, "SecIplist is not following PSR recommendation..!!")
        else:
            messages.warning(request, "SecIplist is following PSR recommendation..!!")

        # print "----validating seclist---------"
        # list1 = ["/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD001",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD002",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-MT001",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-DB001",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD001",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD002",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-MT001",
        #          "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-DB001"]
        # query = Seclist.objects.values_list('name',flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        #
        # missing_seclist = [c for c in list1 if c not in list2]
        # print missing_seclist
        #
        # print "----validating secappln-----"
        # ports = ['1-65535', '22', '25', '53', '80', '111', '123', '143', '389', '443', '514', '515', '601', '631','636',
        #          '1521-1522', '2049', '3128', '3389', '4000', '5986', '24345', '24346', '24347']
        # list1 = []
        # for port in ports:
        #     if port == '1-65535' or '53' or '111' or '123' or '514' or '515' or '601' or '631':
        #         protocol = 'udp'
        #         secappln = protocol + port
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
        #         list1.append(secappln_name)
        #         # csecappln = occ1.createsecappln(protocol, port, secappln_name)
        #         # print csecappln
        #     if port == '1-65535' or '22' or '25' or '53' or '80' or '111' or '123' or '143' or '389' or '443' or '514' or '515' \
        #             or '601' or '631' or '636' or '1521-1522' or '2049' or '3128' or '3389' or '4000' or '5986' or '24345' or '24346' or '24347':
        #         protocol = 'tcp'
        #         secappln = protocol + port
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
        #         list1.append(secappln_name)
        #         # csecappln = occ1.createsecappln(protocol, port, secappln_name)
        #         # print csecappln
        # query = SecApp.objects.values_list('name',flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        #
        # missing_secappln = [c for c in list1 if c not in list2]
        # print missing_secappln
        #
        # print "----validating seciplist-----"
        # list1 = ["/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd",
        #          "/Compute-" + authDomain + "/orchestration/SIL-Bastion",
        #          "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001",
        #          "/Compute-" + authDomain + "/orchestration/SIL-OCNA",
        #          "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain",
        #          "/Compute-" + authDomain + "/orchestration/SIL-ODEM"]
        # query = Secip.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_secip = [c for c in list1 if c not in list2]
        # print missing_secip
        #
        # secipentries = []
        # names = ['SIL-public-internet-idd', 'SIL-Bastion', 'SIL-CustomerHosts001', 'SIL-OCNA',
        #           'SIL-Service-Domain', 'SIL-ODEM']
        # for name in names:
        #     if name == 'SIL-public-internet-idd':
        #         secipentries = ['0.0.0.0/0']
        #     if name == 'SIL-Bastion':
        #         secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
        #                         '143.47.209.32/27', '141.145.31.32/27',
        #                         '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
        #                         '100.64.0.1/32']
        #     if name == 'SIL-CustomerHosts001':
        #         secipentries = ['140.84.230.200/32']
        #     if name == 'SIL-OCNA':
        #         secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
        #                         '160.34.87.0/24',
        #                         '160.34.88.0/23',
        #                         '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
        #                         '160.34.109.0/24',
        #                         '160.34.110.0/24',
        #                         '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
        #                         '160.34.117.0/24',
        #                         '160.34.121.0/24',
        #                         '160.34.126.0/23', '160.34.5.64/27']
        #     if name == 'SIL-Service-Domain':
        #         secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
        #                         '160.34.9.220', '160.34.9.227', '160.34.9.161',
        #                         '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
        #                         '160.34.9.229', '160.34.9.235', '160.34.9.175',
        #                         '141.145.121.161', '141.145.121.159', '141.145.121.148',
        #                         '141.145.121.153',
        #                         '141.145.121.155', '141.145.121.156',
        #                         '141.145.123.69', '141.145.123.68', '141.145.121.142',
        #                         '141.145.121.160',
        #                         '141.145.121.164', '141.145.121.158',
        #                         '141.145.121.157', '141.145.121.50', '140.86.49.110', '140.86.49.114',
        #                         '140.86.49.108', '140.86.49.90',
        #                         '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
        #                         '140.86.49.113', '140.86.49.111', '140.86.51.117',
        #                         '129.144.145.236', '129.144.145.57', '129.144.145.174',
        #                         '129.144.145.226',
        #                         '129.144.145.9', '129.144.145.34', '129.144.145.41', '129.144.145.61',
        #                         '129.144.145.227', '129.144.145.75']
        #     if name == 'SIL-ODEM':
        #         secipentries = ['140.85.107.116/32', '140.85.107.117/32', '140.85.107.118/32',
        #                         '141.146.185.0/25', '141.146.185.160/27', '141.146.130.31/32', '137.254.135.44/32']
        #     secip_name = "/Compute-" + authDomain + "/orchestration/" + name
        #
        # print "----validating secrule-----"
        # list1 =[]
        # secappln = ['tcp1-65535', 'tcp123', 'udp1-65535', 'udp123']
        # for secapp in secappln:
        #     if secapp == 'tcp1-65535':
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
        #         dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + secapp + "SL-" + custname
        #         list1.append(secrule_name)
        #
        #         dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
        #         src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + secapp + "SIL-Service-Domain"
        #         list1.append(secrule_name)
        #     if secapp == 'tcp123':
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
        #         dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
        #         src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + secapp + "SIL-public-internet-idd"
        #         list1.append(secrule_name)
        #     if secapp == 'udp1-65535':
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
        #         dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + secapp + "SL-" + custname
        #         list1.append(secrule_name)
        #
        #         dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
        #         src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + secapp + "SIL-Service-Domain"
        #         list1.append(secrule_name)
        #     if secapp == 'udp123':
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
        #         dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
        #         src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + secapp + "SIL-public-internet-idd"
        #         list1.append(secrule_name)
        #     if secapp == 'tcp3389':
        #         secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
        #         dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + "OMCS- -OTD001"
        #         src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + secapp + "SL-OMCS- -OTD001"
        #         list1.append(secrule_name)
        #
        #         dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + "OMCS- -MT001"
        #         src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001"
        #         secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-CustomerHosts001" + secapp + "SL-OMCS- -MT001"
        #         list1.append(secrule_name)
        # query = SecRule.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_secrule = [c for c in list1 if c not in list2]
        # print missing_secrule
        #
        #
        # print "----validating storage volume------"
        #
        #
        # print "----validating ipreservation------"
        #
        # print "---EOF of Shared N/W ------"
        #
        # print "----validating ipnetwork----------"
        #
        # print "----validating ipnetwork ACLs----------"
        # list1 = ["/Compute-" + authDomain + "ACL-Prod-DB01",
        #          "/Compute-" + authDomain + "ACL-Prod-PubMT01",
        #          "/Compute-" + authDomain + "ACL-Prod-PvtMT01",
        #          "/Compute-" + authDomain + "ACL-Prod-OTD01",
        #          "/Compute-" + authDomain + "ACL-Prod-OTD02",
        #          "/Compute-" + authDomain + "ACL-NonProd-DB01",
        #          "/Compute-" + authDomain + "ACL-NonProd-PubMT01",
        #          "/Compute-" + authDomain + "ACL-NonProd-PvtMT01",
        #          "/Compute-" + authDomain + "ACL-NonProd-OTD01",
        #          "/Compute-" + authDomain + "ACL-PROD-PvtMT01-Net-AD1",
        #          "/Compute-" + authDomain + "ACL-PROD-PvtMT01",
        #          "/Compute-" + authDomain + "ACL-Shared-Infra01",
        #          "/Compute-" + authDomain + "ACL-ALL"]
        # query = ACLs.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_acls = [c for c in list1 if c not in list2]
        # print missing_acls
        #
        # print "----validating ipaddressprefixset----------"
        # list1 = ["/Compute-" + authDomain + "/orchestration/SIL-Bastion",
        #          "/Compute-" + authDomain + "/orchestration/SIL-ODEM",
        #          "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"]
        # query = IpAddrPrefixSets.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_ipaddressprefixset = [c for c in list1 if c not in list2]
        # print missing_ipaddressprefixset
        #
        # if missing_ipaddressprefixset != []:
        #     for item in missing_ipaddressprefixset:
        #         if "SIL-Bastion" in item:
        #             ipAddressPrefixes = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27', '143.47.209.32/27',
        #                                  '141.145.31.32/27', '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27', '100.64.0.1/32']
        #         if "SIL-Service-Domain" in item:
        #             ipAddressPrefixes = ['160.34.9.221/32','160.34.9.230/32','160.34.9.222/32','160.34.9.234/32','160.34.9.220/32',
        #                                  '160.34.9.227/32','160.34.9.161/32','160.34.9.110/32','160.34.9.226/32','160.34.9.228/32',
        #                                  '160.34.9.224/32','160.34.9.229/32','160.34.9.235/32','160.34.9.175/32','141.145.121.161/32',
        #                                  '141.145.121.159/32','141.145.121.148/32','141.145.121.153/32','141.145.121.155/32','141.145.121.156/32',
        #                                  '141.145.123.69/32','141.145.123.68/32','141.145.121.142/32','141.145.121.160/32','141.145.121.164/32',
        #                                  '141.145.121.158/32','141.145.121.157/32','141.145.121.50/32','140.86.49.110/32','140.86.49.114/32',
        #                                  '140.86.49.108/32','140.86.49.90/32','140.86.49.106/32','140.86.49.109/32','140.86.49.112/32',
        #                                  '140.86.49.107/32','140.86.49.113/32','140.86.49.111/32','140.86.51.117/32','129.144.145.236/32',
        #                                  '129.144.145.57/32','129.144.145.174/32','129.144.145.226/32','129.144.145.9/32','129.144.145.34/32',
        #                                  '129.144.145.41/32','129.144.145.61/32','129.144.145.227/32','129.144.145.75/32']
        #         if "SIL-ODEM" in item:
        #             ipAddressPrefixes = ['140.85.107.116/32','140.85.107.117/32','140.85.107.118/32','141.146.185.0/25',
        #                                  '141.146.185.160/27','141.146.130.31/32','137.254.135.44/32']
        #
        # print "------validating Ipnetwork Ipreservation-----"
        #
        #
        # print "-----validating IPnetwork exchange------"
        # list1 = ["/Compute-" + authDomain + "/orchestration/OMCSEXCHANGE-01"]
        # query = IpNetworkExchange.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_ipnetworkexchange = [c for c in list1 if c not in list2]
        # print missing_ipnetworkexchange
        #
        # print "-----validating Prefixdestinationsecrule------"
        #
        #
        # print "----validating secprotocols------"
        # list1 = ["/Compute-" + authDomain + "/orchestration/tcp1-65535", "/Compute-" + authDomain + "/orchestration/tcp22",
        #          "/Compute-" + authDomain + "/orchestration/tcp25", "/Compute-" + authDomain + "/orchestration/tcp53",
        #          "/Compute-" + authDomain + "/orchestration/tcp80", "/Compute-" + authDomain + "/orchestration/tcp111",
        #          "/Compute-" + authDomain + "/orchestration/tcp123", "/Compute-" + authDomain + "/orchestration/tcp143",
        #          "/Compute-" + authDomain + "/orchestration/tcp389", "/Compute-" + authDomain + "/orchestration/tcp443",
        #          "/Compute-" + authDomain + "/orchestration/tcp514", "/Compute-" + authDomain + "/orchestration/tcp515",
        #          "/Compute-" + authDomain + "/orchestration/tcp601", "/Compute-" + authDomain + "/orchestration/tcp631",
        #          "/Compute-" + authDomain + "/orchestration/tcp636", "/Compute-" + authDomain + "/orchestration/tcp1521-1522",
        #          "/Compute-" + authDomain + "/orchestration/tcp2049", "/Compute-" + authDomain + "/orchestration/tcp3128",
        #          "/Compute-" + authDomain + "/orchestration/tcp3389", "/Compute-" + authDomain + "/orchestration/tcp4000",
        #          "/Compute-" + authDomain + "/orchestration/tcp5986", "/Compute-" + authDomain + "/orchestration/tcp24345",
        #          "/Compute-" + authDomain + "/orchestration/tcp24346", "/Compute-" + authDomain + "/orchestration/tcp24347",
        #          "/Compute-" + authDomain + "/orchestration/udp53", "/Compute-" + authDomain + "/orchestration/udp111",
        #          "/Compute-" + authDomain + "/orchestration/udp123", "/Compute-" + authDomain + "/orchestration/udp514",
        #          "/Compute-" + authDomain + "/orchestration/udp601", "/Compute-" + authDomain + "/orchestration/udp515",
        #          "/Compute-" + authDomain + "/orchestration/udp631"]
        # query = SecProtocols.objects.values_list('name', flat=True).order_by('name')
        # list2 = []
        # for item in query:
        #     a = str(item)
        #     list2.append(a)
        # missing_secprotocols = [c for c in list1 if c not in list2]
        # print missing_secprotocols
        #
        # print "----validating vnicsets-----"


        suminst = None

        if 'instbtn' in request.POST:
            inst_ip = request.POST['instbtn']
            print "Rebooting Instance"

            suminst = "true"

            user = listfetchall(list(Instances.objects.values_list('user').distinct().filter(private_ip=inst_ip)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                instance_name = listfetchall(list(Instances.objects.values_list('inst_name').filter(private_ip=inst_ip)))
                desired_state = "shutdown"
                upinstance = occ1.updateInstances(instance_name, desired_state)
                print upinstance

        if 'secrulebtn' in request.POST:
            secrule_name = request.POST['secrulebtn']
            print "Updating Secrule"

            user = listfetchall(list(SecRule.objects.values_list('user').distinct().filter(name=secrule_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                dst_list = listfetchall(list(SecRule.objects.values_list('dst_list').filter(name=secrule_name)))
                src_list = listfetchall(list(SecRule.objects.values_list('src_list').filter(name=secrule_name)))
                application = listfetchall(list(SecRule.objects.values_list('application').filter(name=secrule_name)))
                action = listfetchall(list(SecRule.objects.values_list('action').filter(name=secrule_name)))
                disabled = listfetchall(list(SecRule.objects.values_list('disabled').filter(name=secrule_name)))
                upsecrule = occ1.updatesecrule(dst_list,secrule_name,src_list,application,action,disabled)
                print upsecrule

        if 'seclistbtn' in request.POST:
            seclist_name = request.POST['seclistbtn']
            print "Updating seclist"

            user = listfetchall(list(Seclist.objects.values_list('user').distinct().filter(name=seclist_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                seclist_id = listfetchall(list(Seclist.objects.values_list('name').filter(name=seclist_name)))
                policy = listfetchall(list(Seclist.objects.values_list('policy').filter(name=seclist_name)))
                outbound_cidr_policy = listfetchall(list(Seclist.objects.values_list('outbound_cidr_policy').filter(name=seclist_name)))
                uri = listfetchall(list(Seclist.objects.values_list('uri').filter(name=seclist_name)))
                upseclist = occ1.updateSeclist(policy, uri, outbound_cidr_policy, seclist_id)
                print upseclist

        if 'secappbtn' in request.POST:
            secapp_name = request.POST['secappbtn']
            print "Updating secappln"
            secappln_id = listfetchall(list(SecApp.objects.values_list('name').filter(name=secapp_name)))
            protocol = listfetchall(list(SecApp.objects.values_list('protocol').filter(name=secapp_name)))
            port = listfetchall(list(SecApp.objects.values_list('dport').filter(name=secapp_name)))
            upsecappln = occ.updateSecappln()

        if 'secipbtn' in request.POST:
            secip_name = request.POST['secipbtn']
            print secip_name
            print "Updating secip"

            user = listfetchall(list(Secip.objects.values_list('user').distinct().filter(name=secip_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                secipentries = str(listfetchall(list(Secip.objects.values_list('secipentries').filter(name=secip_name))))

                secipentries = secipentries.replace("[u", "")
                secipentries = secipentries.replace("]", "")
                secipentries = secipentries.replace("'", "")

                description = "updated security IP list"
                secip = [str(secipentries)]
                print secip
                upsecip = occ1.updatesecip(secip_name, secip, description)
                print upsecip


        if 'ipreservebtn' in request.POST:
            ipreserve_name = request.POST['ipreservebtn']
            print "Updating ipreservation"

            user = listfetchall(list(Ipreservation.objects.values_list('user').distinct().filter(name=ipreserve_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                parentpool = listfetchall(list(Ipreservation.objects.values_list('parentpool').filter(name=ipreserve_name)))
                permanent = listfetchall(list(Ipreservation.objects.values_list('permanent').filter(name=ipreserve_name)))
                upipreserve = occ1.updateipreserve(parentpool, permanent, ipreserve_name)
                print upipreserve

        if 'sshbtn' in request.POST:
            ssh_name = request.POST['sshbtn']
            print "Updating sshkey"

            user = listfetchall(list(SSHkeys.objects.values_list('user').distinct().filter(name=ssh_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                enabled = listfetchall(list(SSHkeys.objects.values_list('enabled').filter(ssh_name=ssh_name)))
                key = listfetchall(list(SSHkeys.objects.values_list('key').filter(ssh_name=ssh_name)))
                upssh = occ1.updateSSHkeys(enabled,key,ssh_name)
                print upssh

        if 'storagevolbtn' in request.POST:
            storage_name = request.POST['storagevolbtn']
            print "Updating Storage Volume"

            user = listfetchall(list(StorageVolume.objects.values_list('user').distinct().filter(name=storage_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                p = list(StorageVolume.objects.values_list('size').filter(name=storage_name))
                q = str(p).strip('[]')
                r = str(q).strip('()')  # Data purification
                s = r[:-1]
                t = s[:-1]
                size = str(int(float(t)/(1024.0*1024.0*1024.0))) + "G"
                print "size"
                properties = listfetchall(list(StorageVolume.objects.values_list('properties').filter(name=storage_name)))
                tags = listfetchall(list(StorageVolume.objects.values_list('tags').filter(name=storage_name)))
                description = "Updated Storage Volume"
                upstoragevolume = occ1.updatestoragevolume(size,properties,tags,storage_name,description)
                print upstoragevolume

        # if 'orchbtn' in request.POST:
        #     orch_name = request.POST['orchbtn']
        #     print "updating an Orchestration"
        #     print orch_name
        #     custname = authDomain.upper()
        #     user = listfetchall(list(Orchestration.objects.values_list('user').distinct().filter(name=orch_name)))
        #     usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
        #     passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))
        #
        #     occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
        #     cookies = occ1.login(user=usrname, password=passwd)
        #
        #     if cookies == None:
        #         pass
        #     else:
        #         relationships = []
        #         account = "/Compute-" + authDomain + "/default"
        #         description = "Simple Orchestration"
        #         uri = listfetchall(list(Orchestration.objects.values_list('uri').filter(name=orch_name)))
        #         print "uri"
        #         print uri
        #         name = listfetchall(list(Orchestration.objects.values_list('name').filter(name=orch_name)))
        #         label = custname
        #         obj_type = "launchplan"
        #         ha_policy = "active"
        #         types = "different node"
        #         #shape = listfetchall(list(Instances.objects.values_list('shape').filter(name__contains=orch_name)))
        #         shape = "oc3"
        #         #imagelist = listfetchall(list(Instances.objects.values_list('imagelist').filter(name__contains=name)))
        #         imagelist = "/Compute-omcsservicedom1/jason.rothstein@oracle.com/OPC_OL6_8_X86_64_EBS_OS_VM_12202016"
        #         boot_order = [1]
        #         if shape == None:
        #             shape = "oc3"
        #
        #         index = 1
        #         volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"
        #
        #         dataindex = 2
        #         datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"
        #
        #         # sshkeys = "/Compute-" + authDomain + "/orchestration/" + custname + "-key"
        #         sshkeys = "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT003-key"
        #         tags = custname
        #         #networking_seclists = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + csv_list[i][
        #         #    3] + "-" + csv_list[i][4]
        #         networking_seclists = "/Compute-omcsservicedom1/orchestration/SL-OMCSSERVICEDOM1-NONPROD-MT"
        #         nat = "ipreservation:/Compute-" + authDomain + "/orchestration/" + "US2-CENTRAL-1-" + "DPEE2O-MT001-eip"
        #         dns = custname
        #
        #         #shape = 'oc3'
        #         #imagelist = '/Compute-omcsops/neeraj.k.kumar@oracle.com/Oracle-E-Business-Suite-Provisioning-Image-07292016'
        #         #imagelist = '/Compute-omcsservicedom1/jason.rothstein@oracle.com/OPC_OL6_8_X86_64_EBS_OS_VM_12202016'
        #         uporch = occ1.updateorchestration(relationships, account, name, description, uri, label, obj_type, ha_policy,types,shape,imagelist,boot_order,
        #                                           index, volume, dataindex, datavol, sshkeys, tags,
        #                                           networking_seclists, nat, dns)
        #         print uporch


        if 'orchbtn' in request.POST:
            orch_name = request.POST['orchbtn']
            print "updating an Orchestration"
            print orch_name
            custname = authDomain.upper()
            user = listfetchall(list(Orchestration.objects.values_list('user').distinct().filter(name=orch_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                relationships = []
                account = "/Compute-" + authDomain + "/default"
                description = "Simple Orchestration"
                uri = listfetchall(list(Orchestration.objects.values_list('uri').filter(name=orch_name)))
                print "uri"
                print uri
                name = listfetchall(list(Orchestration.objects.values_list('name').filter(name=orch_name)))
                label = custname
                obj_type = "launchplan"
                ha_policy = "active"
                types = "different node"
                # shape = listfetchall(list(Instances.objects.values_list('shape').filter(name__contains=orch_name)))
                shape = "oc3"
                # imagelist = listfetchall(list(Instances.objects.values_list('imagelist').filter(name__contains=name)))
                imagelist = "/Compute-omcsservicedom1/jason.rothstein@oracle.com/OPC_OL6_8_X86_64_EBS_OS_VM_12202016"
                boot_order = [1]
                if shape == None:
                    shape = "oc3"

                index = 1
                volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"

                dataindex = 2
                datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"

                # sshkeys = "/Compute-" + authDomain + "/orchestration/" + custname + "-key"
                sshkeys = "/Compute-omcsservicedom1/mark.crawford@oracle.com/macrawfo-key"
                tags = custname
                # networking_seclists = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + csv_list[i][
                #    3] + "-" + csv_list[i][4]
                # networking_seclists = "/Compute-omcsservicedom1/orchestration/SL-OMCSSERVICEDOM1-NONPROD-MT"
                # nat = "ipreservation:/Compute-" + authDomain + "/orchestration/" + "US2-CENTRAL-1-" + "DPEE2O-MT001-eip"
                dns = custname

                vnic = "/Compute-" + authDomain + "/orchestration/" + custname + "_eth0"
                is_default_gateway = True
                networking_nat = "network/v1/ipreservation:/Compute-" + authDomain + "/orchestration/" + "US2-CENTRAL-1-" + "DPEE2O-MT001" + "-eip"
                names = ['SL-Prod-DB01-Net-AD1', 'SL-Prod-PubMT01-Net-AD1', 'SL-Prod-PvtMT01-Net-AD1',
                         'SL-Prod-OTD01-Net-AD1', 'SL-NonProd-DB01-Net-AD1',
                         'SL-NonProd-PubMT01-Net-AD1', 'SL-NonProd-PvtMT01-Net-AD1',
                         'SL-NonProd-OTD01-Net-AD1',
                         'SL-Shared-Infra01-Net-AD1', 'SL-Prod-DB01',
                         'SL-Prod-PubMT01', 'SL-Prod-PvtMT01', 'SL-Prod-OTD01', 'SL-NonProd-DB01',
                         'SL-NonProd-PubMT01', 'SL-NonProd-PvtMT01', 'SL-NonProd-OTD01',
                         'SL-Shared-Infra01']
                ipnetwork_name = 'Net-NonProd-PvtMT01-AD2'
                vnicsets = []
                for fname in names:
                    vnicsets = ["/Compute-" + authDomain + "/orchestration/" + fname]
                ipnetwork = "/Compute-" + authDomain + "/orchestration/" + ipnetwork_name

                # shape = 'oc3'
                # imagelist = '/Compute-omcsops/neeraj.k.kumar@oracle.com/Oracle-E-Business-Suite-Provisioning-Image-07292016'
                # imagelist = '/Compute-omcsservicedom1/jason.rothstein@oracle.com/OPC_OL6_8_X86_64_EBS_OS_VM_12202016'
                uporch = occ1.updateiporchestration(relationships, account, name, description, uri, label, obj_type,
                                                    ha_policy, types, shape, imagelist, boot_order,
                                                    index, volume, dataindex, datavol, sshkeys, tags,
                                                    vnic, is_default_gateway, networking_nat, vnicsets,ipnetwork, dns)
                print uporch

        if 'imagebtn' in request.POST:
            image_name = request.POST['imagebtn']
            print "Updating an ImageList"
            user = listfetchall(list(Image.objects.values_list('user').distinct().filter(image_name=image_name)))
            usrname = listfetchall(list(Auth.objects.values_list('username').filter(user=user)))
            passwd = listfetchall(list(Auth.objects.values_list('password').filter(user=user)))

            occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
            cookies = occ1.login(user=usrname, password=passwd)

            if cookies == None:
                pass
            else:
                deflt = list(Image.objects.values_list('deflt').filter(image_name=image_name))
                default = int(str(deflt).strip('[]').strip('()')[:-1][:-1])
                description = listfetchall(list(Image.objects.values_list('description').filter(image_name=image_name)))
                upimage = occ1.updateimage(default,image_name,description)
                print upimage

        connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
        cursord = connection.cursor()
        sql_view3 = "CREATE OR REPLACE VIEW ipreserve_inst as SELECT p1.name,p1.permanent,p1.public_ip,p2.label,p2.user FROM ipreserve as p1 INNER JOIN instances as p2 on p1.name LIKE CONCAT('%',p2.label , '%');"
        cursord.execute(sql_view3)
        cursord = connection.cursor()
        cursord.execute('''select name,permanent,public_ip,label from ipreserve_inst GROUP BY label''')
        ipresereve_data = dictfetchall(cursord)

        connection.commit()
        cursord.close()  # closing connection

        fauthDomain = []            # Global initialization of displayable values
        furl = []
        fstorage = []
        fdccode = []
        fcustcode = []
        faccount = []
        fprivate = []
        fpublic = []
        fipnet = []
        fplatform = []
        data = None
        length = []
        fshape = []
        fimage = []
        ftier = []
        finstance = []
        fsize = []
        size = '32'
        datavolsize = 0
        appinstance = None
        fdatavolsize = []
        fappinstance = []
        fssh = []
        backupvolsize = 0
        fbackupvolsize = []
        hostlabel = 'NULL'
        fhostlabel = []
        seclist = 'NULL'
        fseclist = []
        fpagevolsize = []
        pagevolsize = 'NULL'
        femvolsize = []
        emvolsize = 'NULL'
        fdatacenter = []
        datacenter = 'NULL'
        shapeflag = 0
        datavolflag = 0
        appinstanceflag = 0
        tierflag = 0
        instanceflag = 0
        imageflag = 0
        sshflag = 0
        private_ip='NULL'
        private_custname='NULL'
        public_ip = 'NULL'
        #instname= 'NULL'
        inst_state = 'NULL'
        instlabel = 'NULL'
        #status = 'invalid'
        #db_status = 'ignored'
        fstatus = []
        fdbstatus = []
        missing_secrule = []
        missing_source = []
        missing_dst= []
        missing = []

        p = list(Api.objects.values_list('api').distinct().filter(id__contains=api_id_id))
        q = str(p).strip('[]')
        r = str(q).strip('()')  # Data purification
        s = r[:-1]
        t = s[1:]
        u = t[:-1]
        zones = u[1:]

        p = list(Instances.objects.values_list('imagelist').filter(api_id_id__in=api_id_id))  # Collecting api from authDomain
        q = str(p).strip('[]')
        r = str(q).strip('()')  # Data purification
        s = r[:-1]
        t = s[1:]
        u = t[:-1]
        imagelist = u[1:]

        SecRule.objects.values_list('name').filter(api_id_id__in=api_id_id)
        Secip.objects.values_list('name').filter(api_id_id__in=api_id_id)
        # Load documents for the list page
        documents = Document.objects.all()

        # uploading the input file
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():     # Form validation & save the content
            newdoc = Document(docfile=request.FILES['docfile'], user=request.session['username'])
            newdoc.save()

        user = request.session['username']

        if not documents:       # whether the document is empty ....!!
            print "Empty doc"
        else:
            print "Executing Document....!!"# Executing the content of the document
            # file = "C:\Users\\prajshet\\Desktop\\Infra_atmn\\BMCS\\machines.xlsx"
            # workbook = xlrd.open_workbook(file)     # getting the data of the .xlsx file
            # sheet = workbook.sheet_by_index(0)
            # row = range(sheet.nrows)                # Read from 1st row & discard header row
            # data = [[sheet.cell_value(r, c) for c in range(sheet.ncols)] for r in row[1:]]

            file = "C:\Users\\prajshet\\Desktop\\Infra_atmn\\BMCS\\machines.csv"
            with open(file) as f:
                reader = csv.reader(f)
                csv_list = list(reader)

            print "network radio button"
            network = request.POST.get('network', '')
            print network
            print "product radio button"
            product = request.POST.get('product', '')
            print product


            if 'validbtn' in request.POST:
                messages.warning(request, "--------missing rules--------")
                if network == 'sharedbtn':
                    for i in range(1, len(csv_list)):
                        print "----validating seclist---------"
                        list1 = ["/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD001",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD002",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-MT001",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-DB001",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD001",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD002",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-MT001",
                                 "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-DB001"]
                        query = Seclist.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)

                        missing_seclist = [c for c in list1 if c not in list2]
                        print missing_seclist

                        print "----validating secappln-----"
                        ports = ['1-65535', '22', '25', '53', '80', '111', '123', '143', '389', '443', '514', '515',
                                 '601',
                                 '631', '636',
                                 '1521-1522', '2049', '3128', '3389', '4000', '5986', '24345', '24346', '24347']
                        list1 = []
                        for port in ports:
                            if port == '1-65535' or '53' or '111' or '123' or '514' or '515' or '601' or '631':
                                protocol = 'udp'
                                secappln = protocol + port
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                list1.append(secappln_name)
                                # csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                # print csecappln
                            if port == '1-65535' or '22' or '25' or '53' or '80' or '111' or '123' or '143' or '389' or '443' or '514' or '515' \
                                    or '601' or '631' or '636' or '1521-1522' or '2049' or '3128' or '3389' or '4000' or '5986' or '24345' or '24346' or '24347':
                                protocol = 'tcp'
                                secappln = protocol + port
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                list1.append(secappln_name)
                                # csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                # print csecappln
                        query = SecApp.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)

                        missing_secappln = [c for c in list1 if c not in list2]
                        print missing_secappln

                        print "----validating seciplist-----"
                        list1 = ["/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd",
                                 "/Compute-" + authDomain + "/orchestration/SIL-Bastion",
                                 "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001",
                                 "/Compute-" + authDomain + "/orchestration/SIL-OCNA",
                                 "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain",
                                 "/Compute-" + authDomain + "/orchestration/SIL-ODEM"]
                        query = Secip.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_secip = [c for c in list1 if c not in list2]
                        print missing_secip

                        secipentries = []
                        names = ['SIL-public-internet-idd', 'SIL-Bastion', 'SIL-CustomerHosts001', 'SIL-OCNA',
                                 'SIL-Service-Domain', 'SIL-ODEM']
                        for name in names:
                            if name == 'SIL-public-internet-idd':
                                secipentries = ['0.0.0.0/0']
                            if name == 'SIL-Bastion':
                                secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                '143.47.209.32/27', '141.145.31.32/27',
                                                '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
                                                '100.64.0.1/32']
                            if name == 'SIL-CustomerHosts001':
                                secipentries = ['140.84.230.200/32']
                            if name == 'SIL-OCNA':
                                secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
                                                '160.34.87.0/24',
                                                '160.34.88.0/23',
                                                '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
                                                '160.34.109.0/24',
                                                '160.34.110.0/24',
                                                '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
                                                '160.34.117.0/24',
                                                '160.34.121.0/24',
                                                '160.34.126.0/23', '160.34.5.64/27']
                            if name == 'SIL-Service-Domain':
                                secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
                                                '160.34.9.220', '160.34.9.227', '160.34.9.161',
                                                '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
                                                '160.34.9.229', '160.34.9.235', '160.34.9.175',
                                                '141.145.121.161', '141.145.121.159', '141.145.121.148',
                                                '141.145.121.153',
                                                '141.145.121.155', '141.145.121.156',
                                                '141.145.123.69', '141.145.123.68', '141.145.121.142',
                                                '141.145.121.160',
                                                '141.145.121.164', '141.145.121.158',
                                                '141.145.121.157', '141.145.121.50', '140.86.49.110', '140.86.49.114',
                                                '140.86.49.108', '140.86.49.90',
                                                '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
                                                '140.86.49.113', '140.86.49.111', '140.86.51.117',
                                                '129.144.145.236', '129.144.145.57', '129.144.145.174',
                                                '129.144.145.226',
                                                '129.144.145.9', '129.144.145.34', '129.144.145.41', '129.144.145.61',
                                                '129.144.145.227', '129.144.145.75']
                            if name == 'SIL-ODEM':
                                secipentries = ['140.85.107.116/32', '140.85.107.117/32', '140.85.107.118/32',
                                                '141.146.185.0/25', '141.146.185.160/27', '141.146.130.31/32',
                                                '137.254.135.44/32']
                            secip_name = "/Compute-" + authDomain + "/orchestration/" + name

                        print "----validating secrule-----"
                        list1 = []
                        secappln = ['tcp1-65535', 'tcp123', 'udp1-65535', 'udp123']
                        for secapp in secappln:
                            if secapp == 'tcp1-65535':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custname
                                list1.append(secrule_name)

                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SL-" + custname + "_" + secapp + "_" + "SIL-Service-Domain"
                                list1.append(secrule_name)
                            if secapp == 'tcp123':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SL-" + custname + "_" + secapp + "_" + "SIL-public-internet-idd"
                                list1.append(secrule_name)
                            if secapp == 'udp1-65535':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custname
                                list1.append(secrule_name)

                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SL-" + custname + "_" + secapp + "_" + "SIL-Service-Domain"
                                list1.append(secrule_name)
                            if secapp == 'udp123':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SL-" + custname + "_" + secapp + "_" + "SIL-public-internet-idd"
                                list1.append(secrule_name)
                            if secapp == 'tcp3389':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + "OMCS-" + csv_list[i][3] + "-OTD001"
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custcode + "-" + \
                                               csv_list[i][3] + "-OTD001"
                                list1.append(secrule_name)

                                dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + "OMCS-" + csv_list[i][3] + "-MT001"
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-CustomerHosts001" + "_" + secapp+ "_" + "SL-" + custcode + "-" + csv_list[i][3] + "-MT001"
                                list1.append(secrule_name)
                        query = SecRule.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_secrule = [c for c in list1 if c not in list2]
                        print missing_secrule

                        for item in missing_secrule:
                            ext = '/orchestration/Rule_'
                            pattern = item[item.find(ext) + len(ext):]
                            strpattern = re.split(r'_', pattern)
                            private_ip = None
                            secipentries = None
                            if 'SL' in strpattern[0]:
                                private_ip = listfetchall(list(Orchestration.objects.values_list('private_ip').distinct().filter(inst_seclist__contains=strpattern[0])))
                            elif 'SL' in strpattern[2]:
                                private_ip = listfetchall(list(Orchestration.objects.values_list('private_ip').distinct().filter(inst_seclist__contains=strpattern[2])))

                            if 'SIL-public-internet-idd' in strpattern[0] or strpattern[2]:
                                secipentries = ['0.0.0.0/0']
                            if 'SIL-Bastion' in strpattern[0] or strpattern[2]:
                                secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                '143.47.209.32/27', '141.145.31.32/27',
                                                '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
                                                '100.64.0.1/32']
                            if 'SIL-CustomerHosts001' in strpattern[0] or strpattern[2]:
                                secipentries = ['140.84.230.200/32']
                            if 'SIL-OCNA' in strpattern[0] or strpattern[2]:
                                secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
                                                '160.34.87.0/24',
                                                '160.34.88.0/23',
                                                '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
                                                '160.34.109.0/24',
                                                '160.34.110.0/24',
                                                '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
                                                '160.34.117.0/24',
                                                '160.34.121.0/24',
                                                '160.34.126.0/23', '160.34.5.64/27']
                            if 'SIL-Service-Domain' in strpattern[0] or strpattern[2]:
                                secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
                                                '160.34.9.220', '160.34.9.227', '160.34.9.161',
                                                '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
                                                '160.34.9.229', '160.34.9.235', '160.34.9.175',
                                                '141.145.121.161', '141.145.121.159', '141.145.121.148',
                                                '141.145.121.153',
                                                '141.145.121.155', '141.145.121.156',
                                                '141.145.123.69', '141.145.123.68', '141.145.121.142',
                                                '141.145.121.160',
                                                '141.145.121.164', '141.145.121.158',
                                                '141.145.121.157', '141.145.121.50', '140.86.49.110', '140.86.49.114',
                                                '140.86.49.108', '140.86.49.90',
                                                '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
                                                '140.86.49.113', '140.86.49.111', '140.86.51.117',
                                                '129.144.145.236', '129.144.145.57', '129.144.145.174',
                                                '129.144.145.226',
                                                '129.144.145.9', '129.144.145.34', '129.144.145.41', '129.144.145.61',
                                                '129.144.145.227', '129.144.145.75']
                            if 'SIL-ODEM' in strpattern[0] or strpattern[2]:
                                secipentries = ['140.85.107.116/32', '140.85.107.117/32', '140.85.107.118/32',
                                                '141.146.185.0/25', '141.146.185.160/27', '141.146.130.31/32',
                                                '137.254.135.44/32']
                            messages.success(request, "Secrule : {0}".format(item))
                            messages.warning(request, "Source : {0}".format(strpattern[0]))
                            messages.warning(request, "Destination : {0}".format(strpattern[2]))
                            messages.warning(request, "Seclist IP: {0}".format(private_ip))
                            messages.warning(request, "Secipentries: {0}".format(secipentries))
                            messages.warning(request, "Protocol&Port : {0}".format(strpattern[1]))
                            missing_source.append(strpattern[0])
                            missing_dst.append(strpattern[2])
                            missing = zip(missing_secrule,missing_source,missing_dst)

                        for item in missing_seclist:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "Seclist name : {0}".format(item))
                            messages.warning(request, "Seclist: {0}".format(pattern))

                        for item in missing_secip:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "SecIp name : {0}".format(item))
                            messages.warning(request, "SecIp: {0}".format(pattern))

                        for item in missing_secappln:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "SecApplication name : {0}".format(item))
                            messages.warning(request, "Protocol & Port: {0}".format(pattern))


                        print "----validating storage volume------"

                        print "----validating ipreservation------"
                        # messages.warning(request, "--------missing rules--------")
                        # messages.warning(request, "Seclist : {0}".format(missing_seclist))
                        # messages.warning(request, "SecIplist : {0}".format(missing_secip))
                        # messages.warning(request, "Security Appliction : {0}".format(missing_secappln))
                        # messages.warning(request, "Secrule : {0}".format(missing_secrule))
                        # messages.success(request,
                        #                  "If you wanna create these missing rules, then click on 'Orchestrate' button")

                elif network == 'ipbtn':
                    for i in range(1, len(csv_list)):
                        print "----validating ipnetwork----------"

                        print "----validating ipnetwork ACLs----------"
                        list1 = ["/Compute-" + authDomain + "/orchestration/ACL-PROD-DB01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-PUBMT01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-PVTMT01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-OTD01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-OTD02",
                                 "/Compute-" + authDomain + "/orchestration/ACL-NONPROD-DB01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-NONPROD-PUBMT01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-NONPROD-PVTMT01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-NONPROD-OTD01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-PVTMT01-NET-AD1",
                                 "/Compute-" + authDomain + "/orchestration/ACL-PROD-PVTMT01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-SHARED-INFRA01",
                                 "/Compute-" + authDomain + "/orchestration/ACL-ALL"]
                        query = ACLs.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_acls = [c for c in list1 if c not in list2]
                        print missing_acls

                        print "----validating ipaddressprefixset----------"
                        list1 = ["/Compute-" + authDomain + "/orchestration/SIL-Bastion",
                                 "/Compute-" + authDomain + "/orchestration/SIL-ODEM",
                                 "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"]
                        query = IpAddrPrefixSets.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_ipaddressprefixset = [c for c in list1 if c not in list2]
                        print missing_ipaddressprefixset

                        if missing_ipaddressprefixset != []:
                            for item in missing_ipaddressprefixset:
                                if "SIL-Bastion" in item:
                                    ipAddressPrefixes = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                         '143.47.209.32/27',
                                                         '141.145.31.32/27', '141.145.47.160/27', '160.34.5.64/27',
                                                         '129.152.34.32/27', '100.64.0.1/32']
                                if "SIL-Service-Domain" in item:
                                    ipAddressPrefixes = ['160.34.9.221/32', '160.34.9.230/32', '160.34.9.222/32',
                                                         '160.34.9.234/32', '160.34.9.220/32',
                                                         '160.34.9.227/32', '160.34.9.161/32', '160.34.9.110/32',
                                                         '160.34.9.226/32', '160.34.9.228/32',
                                                         '160.34.9.224/32', '160.34.9.229/32', '160.34.9.235/32',
                                                         '160.34.9.175/32', '141.145.121.161/32',
                                                         '141.145.121.159/32', '141.145.121.148/32',
                                                         '141.145.121.153/32',
                                                         '141.145.121.155/32', '141.145.121.156/32',
                                                         '141.145.123.69/32', '141.145.123.68/32', '141.145.121.142/32',
                                                         '141.145.121.160/32', '141.145.121.164/32',
                                                         '141.145.121.158/32', '141.145.121.157/32',
                                                         '141.145.121.50/32',
                                                         '140.86.49.110/32', '140.86.49.114/32',
                                                         '140.86.49.108/32', '140.86.49.90/32', '140.86.49.106/32',
                                                         '140.86.49.109/32', '140.86.49.112/32',
                                                         '140.86.49.107/32', '140.86.49.113/32', '140.86.49.111/32',
                                                         '140.86.51.117/32', '129.144.145.236/32',
                                                         '129.144.145.57/32', '129.144.145.174/32',
                                                         '129.144.145.226/32',
                                                         '129.144.145.9/32', '129.144.145.34/32',
                                                         '129.144.145.41/32', '129.144.145.61/32', '129.144.145.227/32',
                                                         '129.144.145.75/32']
                                if "SIL-ODEM" in item:
                                    ipAddressPrefixes = ['140.85.107.116/32', '140.85.107.117/32', '140.85.107.118/32',
                                                         '141.146.185.0/25',
                                                         '141.146.185.160/27', '141.146.130.31/32', '137.254.135.44/32']

                        print "------validating Ipnetwork Ipreservation-----"

                        print "-----validating IPnetwork exchange------"
                        list1 = ["/Compute-" + authDomain + "/orchestration/OMCSEXCHANGE-01"]
                        query = IpNetworkExchange.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_ipnetworkexchange = [c for c in list1 if c not in list2]
                        print missing_ipnetworkexchange

                        print "-----validating Prefixdestinationsecrule------"

                        print "----validating secprotocols------"
                        list1 = ["/Compute-" + authDomain + "/orchestration/tcp1-65535",
                                 "/Compute-" + authDomain + "/orchestration/tcp22",
                                 "/Compute-" + authDomain + "/orchestration/tcp25",
                                 "/Compute-" + authDomain + "/orchestration/tcp53",
                                 "/Compute-" + authDomain + "/orchestration/tcp80",
                                 "/Compute-" + authDomain + "/orchestration/tcp111",
                                 "/Compute-" + authDomain + "/orchestration/tcp123",
                                 "/Compute-" + authDomain + "/orchestration/tcp143",
                                 "/Compute-" + authDomain + "/orchestration/tcp389",
                                 "/Compute-" + authDomain + "/orchestration/tcp443",
                                 "/Compute-" + authDomain + "/orchestration/tcp514",
                                 "/Compute-" + authDomain + "/orchestration/tcp515",
                                 "/Compute-" + authDomain + "/orchestration/tcp601",
                                 "/Compute-" + authDomain + "/orchestration/tcp631",
                                 "/Compute-" + authDomain + "/orchestration/tcp636",
                                 "/Compute-" + authDomain + "/orchestration/tcp1521-1522",
                                 "/Compute-" + authDomain + "/orchestration/tcp2049",
                                 "/Compute-" + authDomain + "/orchestration/tcp3128",
                                 "/Compute-" + authDomain + "/orchestration/tcp3389",
                                 "/Compute-" + authDomain + "/orchestration/tcp4000",
                                 "/Compute-" + authDomain + "/orchestration/tcp5986",
                                 "/Compute-" + authDomain + "/orchestration/tcp24345",
                                 "/Compute-" + authDomain + "/orchestration/tcp24346",
                                 "/Compute-" + authDomain + "/orchestration/tcp24347",
                                 "/Compute-" + authDomain + "/orchestration/udp53",
                                 "/Compute-" + authDomain + "/orchestration/udp111",
                                 "/Compute-" + authDomain + "/orchestration/udp123",
                                 "/Compute-" + authDomain + "/orchestration/udp514",
                                 "/Compute-" + authDomain + "/orchestration/udp601",
                                 "/Compute-" + authDomain + "/orchestration/udp515",
                                 "/Compute-" + authDomain + "/orchestration/udp631"]
                        query = SecProtocols.objects.values_list('name', flat=True).order_by('name')
                        list2 = []
                        for item in query:
                            a = str(item)
                            list2.append(a)
                        missing_secprotocols = [c for c in list1 if c not in list2]
                        print missing_secprotocols

                        print "----validating vnicsets-----"

                        for item in missing_acls:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "IpNetwork ACL : {0}".format(item))
                            messages.warning(request, "ACL: {0}".format(pattern))

                        for item in missing_ipaddressprefixset:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "IpAddressPrefixSets name : {0}".format(item))
                            messages.warning(request, "IpAddressPrefixSets: {0}".format(pattern))

                        for item in missing_ipnetworkexchange:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "IpNetworkExchange name : {0}".format(item))
                            messages.warning(request, "IpNetworkExchange: {0}".format(pattern))

                        for item in missing_secprotocols:
                            ext = '/orchestration/'
                            pattern = item[item.find(ext) + len(ext):]
                            messages.success(request, "SecProtocol name : {0}".format(item))
                            messages.warning(request, "Protocol & Port: {0}".format(pattern))

                        # messages.warning(request, "--------missing rules--------")
                        # messages.warning(request, "IpNetwork ACLs : {0}".format(missing_acls))
                        # messages.warning(request, "IpAddressPrefixSets : {0}".format(missing_ipaddressprefixset))
                        # messages.warning(request, "IpNetworkingExchange : {0}".format(missing_ipnetworkexchange))
                        # messages.warning(request, "SecProtocols : {0}".format(missing_secprotocols))
                        # messages.success(request,
                        #                  "If you wanna create these missing rules, then click on 'Orchestrate' button")
                messages.success(request,
                                 "If you wanna create these missing rules, then click on 'Orchestrate' button")

            if 'sharedbtn' in request.POST:
                print "network orch"
                network = request.POST.get('network', '')
                print network
                print "product orch"
                product = request.POST.get('product', '')
                print product

                if network == 'sharedbtn':
                    print "shared stuff"
                    for i in range(1, len(csv_list)):
                        usrname = listfetchall(list(Auth.objects.values_list('username').distinct()))
                        passwd = listfetchall(list(Auth.objects.values_list('password').distinct()))

                        occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
                        print occ1
                        cookies = occ1.login(user=usrname, password=passwd)
                        print cookies
                        if cookies == None:
                            pass
                        else:
                            print "Creating IpReservation"
                            # hostlabel = 'EM2-Z17-DPEE2O-MT001'  # user input
                            hostlabel = csv_list[i][6] + "-" + csv_list[i][1] + "-" + csv_list[i][4] + "001"
                            parentpool = "/oracle/public/ippool"
                            permanent = True

                            fname = "/Compute-" + authDomain + "/orchestration/"
                            sname = os.path.join(fname, hostlabel)
                            # name = "/Compute-omcsops/orchestration/EM2-Z17-DPEE2O-MT001-eip"  # concatenate
                            kname = sname + '-eip'
                            crtipreserve = occ1.createipreserve(parentpool, permanent, kname)
                            print crtipreserve

                            print "####################################"
                            print "Create SSH key"
                            dir_name = '/home/opc/sshdir'
                            base = os.path.join(dir_name, user)
                            basepath = os.path.join(base, csv_list[i][1])
                            print basepath

                            os.system('ssh-keygen -b 4096 -t rsa -N "" -C "" -f ' + basepath)
                            # li = os.listdir('/tmp/sshdir')
                            # f = open('/home/opc/sshdir' + li[0], 'r')
                            # public_key = f.read()
                            # f = open('/home/opc/sshdir' + li[1], 'r')
                            # private_key = f.read()
                            # li = os.listdir('/home/opc/sshdir')
                            # f = open('/home/opc/sshdir/' + li[0], 'r')
                            # private_key = f.read()
                            # f = open('/home/opc/sshdir/' + li[1], 'r')
                            # public_key = f.read()
                            li = os.listdir(base)
                            f = open(base + "/" + li[0], 'r')
                            private_key = f.read()
                            f = open(base + "/" + li[1], 'r')
                            public_key = f.read()

                            enabled = True
                            key = public_key
                            name = sname + '-key'
                            csshkey = occ1.createsshkey(enabled, key, name)
                            print csshkey

                            print "######################################"

                            print "Creating Seclist"
                            custname = authDomain.upper()
                            policy = "DENY"
                            outbound_cidr_policy = "REJECT"

                            list1 = ["/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD001",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-OTD002",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-MT001",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-PROD-DB001",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD001",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-OTD002",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-MT001",
                                     "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-NONPROD-DB001"]
                            query = Seclist.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)

                            missing_seclist = [c for c in list1 if c not in list2]
                            print missing_seclist

                            for item in missing_seclist:
                                cseclist = occ1.createseclist(policy, outbound_cidr_policy, item)
                                print cseclist
                            seclist_name = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + \
                                           csv_list[i][3] + "-" + csv_list[i][4]
                            cseclist = occ1.createseclist(policy, outbound_cidr_policy, seclist_name)
                            print cseclist

                            print "Creating Secappln"
                            ports = ['1-65535', '22', '25', '53', '80', '111', '123', '143', '389', '443', '514', '515',
                                     '601','631', '636',
                                     '1521-1522', '2049', '3128', '3389', '4000', '5986', '24345', '24346', '24347']
                            list1 = []
                            for port in ports:
                                if port == '1-65535' or '53' or '111' or '123' or '514' or '515' or '601' or '631':
                                    protocol = 'udp'
                                    secappln = protocol + port
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                    list1.append(secappln_name)
                                    # csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                    # print csecappln
                                if port == '1-65535' or '22' or '25' or '53' or '80' or '111' or '123' or '143' or '389' or '443' or '514' or '515' \
                                        or '601' or '631' or '636' or '1521-1522' or '2049' or '3128' or '3389' or '4000' or '5986' or '24345' or '24346' or '24347':
                                    protocol = 'tcp'
                                    secappln = protocol + port
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                    list1.append(secappln_name)
                                    # csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                    # print csecappln
                            query = SecApp.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)

                            missing_secappln = [c for c in list1 if c not in list2]
                            print missing_secappln


                            protocols = ['tcp', 'udp']
                            # ports = ['1-65535', '22', '25', '53', '80', '111', '123', '389', '443', '514', '601', '636',
                            #          '2049',
                            #          '3128', '3389', '5986', '24345', '24346', '24347']
                            ports = ['1-65535', '22', '25', '53', '80', '111', '123', '143', '389', '443', '514', '515',
                                     '601','631', '636',
                                     '1521-1522', '2049', '3128', '3389', '4000', '5986', '24345', '24346', '24347']
                            for port in ports:
                                if port == '1-65535' or '53' or '111' or '123' or '514' or '515' or '601' or '631':
                                    protocol = 'udp'
                                    secappln = protocol + port
                                    for item in missing_secappln:
                                        if port in item:
                                            csecappln = occ1.createsecappln(protocol, port, item)
                                            print csecappln
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                    csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                    print csecappln
                                if port == '1-65535' or '22' or '25' or '53' or '80' or '111' or '123' or '143' or '389' or '443' or '514' or '515' \
                                        or '601' or '631' or '636' or '1521-1522' or '2049' or '3128' or '3389' or '4000' or '5986' or '24345' or '24346' or '24347':
                                    protocol = 'tcp'
                                    secappln = protocol + port
                                    for item in missing_secappln:
                                        if port in item:
                                            csecappln = occ1.createsecappln(protocol, port, item)
                                            print csecappln
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                    csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                    print csecappln

                            print "Creating Seciplist"
                            list1 = ["/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd",
                                     "/Compute-" + authDomain + "/orchestration/SIL-Bastion",
                                     "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001",
                                     "/Compute-" + authDomain + "/orchestration/SIL-OCNA",
                                     "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain",
                                     "/Compute-" + authDomain + "/orchestration/SIL-ODEM"]
                            query = Secip.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_secip = [c for c in list1 if c not in list2]
                            print missing_secip

                            for item in missing_secip:
                                if 'SIL-public-internet-idd' in item:
                                    secipentries = ['0.0.0.0/0']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-public-internet-idd'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist
                                if 'SIL-Bastion' in item:
                                    secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                    '143.47.209.32/27', '141.145.31.32/27',
                                                    '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
                                                    '100.64.0.1/32']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-Bastion'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist
                                if 'SIL-CustomerHosts001' in item:
                                    secipentries = ['140.84.230.200/32']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-CustomerHosts001'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist
                                if 'SIL-OCNA' in item:
                                    secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
                                                    '160.34.87.0/24',
                                                    '160.34.88.0/23',
                                                    '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
                                                    '160.34.109.0/24',
                                                    '160.34.110.0/24',
                                                    '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
                                                    '160.34.117.0/24',
                                                    '160.34.121.0/24',
                                                    '160.34.126.0/23', '160.34.5.64/27']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-OCNA'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist
                                if 'SIL-Service-Domain' in item:
                                    secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
                                                    '160.34.9.220', '160.34.9.227', '160.34.9.161',
                                                    '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
                                                    '160.34.9.229', '160.34.9.235', '160.34.9.175',
                                                    '141.145.121.161', '141.145.121.159', '141.145.121.148',
                                                    '141.145.121.153',
                                                    '141.145.121.155', '141.145.121.156',
                                                    '141.145.123.69', '141.145.123.68', '141.145.121.142',
                                                    '141.145.121.160',
                                                    '141.145.121.164', '141.145.121.158',
                                                    '141.145.121.157', '141.145.121.50', '140.86.49.110',
                                                    '140.86.49.114',
                                                    '140.86.49.108', '140.86.49.90',
                                                    '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
                                                    '140.86.49.113', '140.86.49.111', '140.86.51.117',
                                                    '129.144.145.236', '129.144.145.57', '129.144.145.174',
                                                    '129.144.145.226',
                                                    '129.144.145.9', '129.144.145.34', '129.144.145.41',
                                                    '129.144.145.61',
                                                    '129.144.145.227', '129.144.145.75']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-Service-Domain'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist
                                if 'SIL-ODEM' in item:
                                    secipentries = ['140.85.107.116/32', '140.85.107.117/32', '140.85.107.118/32',
                                                    '141.146.185.0/25', '141.146.185.160/27', '141.146.130.31/32',
                                                    '137.254.135.44/32']
                                    secip_name = "/Compute-" + authDomain + "/orchestration/" + 'SIL-ODEM'
                                    cseciplist = occ1.createseciplist(secip_name, secipentries)
                                    print cseciplist

                            # secipentries = []
                            # names = ['SIL-public-internet-idd', 'SIL-Bastion', 'SIL-CustomerHosts001', 'SIL-OCNA',
                            #          'SIL-OMCS-Infrastructure', 'SIL-OPC-StorageCloud', 'SIL-Service-Domain',
                            #          'SIL-Qualys']
                            # for name in names:
                            #     if name == 'SIL-public-internet-idd':
                            #         secipentries = ['0.0.0.0/0']
                            #     if name == 'SIL-Bastion':
                            #         secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                            #                         '143.47.209.32/27', '141.145.31.32/27',
                            #                         '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
                            #                         '100.64.0.1/32']
                            #     if name == 'SIL-CustomerHosts001':
                            #         secipentries = ['140.84.230.200/32']
                            #     if name == 'SIL-OCNA':
                            #         secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
                            #                         '160.34.87.0/24',
                            #                         '160.34.88.0/23',
                            #                         '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
                            #                         '160.34.109.0/24',
                            #                         '160.34.110.0/24',
                            #                         '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
                            #                         '160.34.117.0/24',
                            #                         '160.34.121.0/24',
                            #                         '160.34.126.0/23', '160.34.5.64/27']
                            #     if name == 'SIL-OMCS-Infrastructure':
                            #         secipentries = ['148.87.235.208/29', '10.154.222.0/23', '10.154.224.0/23',
                            #                         '10.231.229.24/29', '129.155.244.128/29',
                            #                         '129.155.244.144/28', '137.254.128.13/32', '137.254.129.32/28',
                            #                         '137.254.129.48/29', '137.254.135.40/29',
                            #                         '137.254.184.0/21', '140.83.230.0/28', '140.83.230.64/26',
                            #                         '140.85.0.0/16',
                            #                         '141.146.128.12/32',
                            #                         '141.146.129.152/29', '141.146.129.160/29', '141.146.130.0/25',
                            #                         '141.146.130.128/27', '141.146.131.120/29',
                            #                         '141.146.154.0/23', '141.146.156.0/24', '141.146.158.0/24',
                            #                         '141.146.159.64/26', '141.146.159.128/25',
                            #                         '141.146.185.0/24', '141.146.190.0/28', '141.146.200.16/28',
                            #                         '141.146.226.0/23', '141.146.232.0/21', '144.20.7.32/28',
                            #                         '144.20.7.112/29', '144.20.12.136/29', '144.20.27.64/29',
                            #                         '144.20.30.0/23',
                            #                         '144.20.48.48/28', '144.20.48.64/27',
                            #                         '144.20.48.112/28', '144.20.48.128/27', '144.20.49.24/29',
                            #                         '144.20.49.128/29', '144.20.50.0/23', '144.20.52.0/29',
                            #                         '144.20.52.40/29', '144.20.52.48/29', '144.20.52.88/29',
                            #                         '144.20.52.96/29',
                            #                         '144.20.52.136/29', '144.20.52.144/29',
                            #                         '144.20.52.192/28', '144.20.55.32/28', '144.20.55.240/28',
                            #                         '144.20.59.48/28', '144.20.59.104/29', '144.20.59.112/29',
                            #                         '144.20.59.152/29', '144.20.59.160/29', '144.20.59.200/29',
                            #                         '144.20.59.208/29', '144.20.59.248/29', '144.20.63.0/28',
                            #                         '144.20.63.32/27', '144.20.63.128/27', '144.20.63.192/29',
                            #                         '144.20.63.208/28', '144.20.83.48/29', '144.20.83.144/29',
                            #                         '144.20.98.0/25', '144.20.99.64/26', '144.20.108.248/29',
                            #                         '144.20.116.0/26',
                            #                         '144.20.191.80/28', '144.20.227.0/24', '141.146.128.0/17',
                            #                         '10.224.0.0/14',
                            #                         '100.64.1.1/29', '100.64.1.16/29']
                            #     if name == 'SIL-OPC-StorageCloud':
                            #         secipentries = ['129.152.32.0/23', '160.34.0.0/23', '160.34.2.0/23',
                            #                         '160.34.5.0/27',
                            #                         '160.34.14.32/27', '129.152.172.0/23']
                            #     if name == 'SIL-Service-Domain':
                            #         secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
                            #                         '160.34.9.220', '160.34.9.227', '160.34.9.161',
                            #                         '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
                            #                         '160.34.9.229', '160.34.9.235', '160.34.9.175',
                            #                         '141.145.121.161', '141.145.121.159', '141.145.121.148',
                            #                         '141.145.121.153',
                            #                         '141.145.121.155', '141.145.121.156',
                            #                         '141.145.123.69', '141.145.123.68', '141.145.121.142',
                            #                         '141.145.121.160',
                            #                         '141.145.121.164', '141.145.121.158',
                            #                         '141.145.121.157', '141.145.121.50', '140.86.49.110',
                            #                         '140.86.49.114',
                            #                         '140.86.49.108', '140.86.49.90',
                            #                         '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
                            #                         '140.86.49.113', '140.86.49.111', '140.86.51.117',
                            #                         '129.144.145.236', '129.144.145.57', '129.144.145.174',
                            #                         '129.144.145.226',
                            #                         '129.144.145.9', '129.144.145.34', '129.144.145.41',
                            #                         '129.144.145.61',
                            #                         '129.144.145.227', '129.144.145.75']
                            #     if name == 'SIL-Qualys':
                            #         secipentries = ['207.238.80.72/32', '207.238.80.73/32', '207.238.80.74/32',
                            #                         '207.238.80.75/32', '207.238.80.76/32']
                            #     secip_name = "/Compute-" + authDomain + "/orchestration/" + name
                            #     cseciplist = occ1.createseciplist(secip_name, secipentries)
                            #     print cseciplist

                            print "Creating Secrule"
                            list1 = []
                            secappln = ['tcp1-65535', 'tcp123', 'udp1-65535', 'udp123']
                            for secapp in secappln:
                                if secapp == 'tcp1-65535':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custname
                                    list1.append(secrule_name)

                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "_" + secapp + "_" + "SIL-Service-Domain"
                                    list1.append(secrule_name)
                                if secapp == 'tcp123':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "_" + secapp + "_" + "SIL-public-internet-idd"
                                    list1.append(secrule_name)
                                if secapp == 'udp1-65535':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custname
                                    list1.append(secrule_name)

                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "_" + secapp + "_" + "SIL-Service-Domain"
                                    list1.append(secrule_name)
                                if secapp == 'udp123':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "_" + secapp + "_" + "SIL-public-internet-idd"
                                    list1.append(secrule_name)
                                if secapp == 'tcp3389':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custcode + "-" + \
                                                   csv_list[i][3] +"-OTD001"
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + "SL-" + custcode + "-" + \
                                                   csv_list[i][3] + "-OTD001"
                                    list1.append(secrule_name)

                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custcode + "-" + \
                                                   csv_list[i][3] + "-MT001"
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-CustomerHosts001" + "_" + secapp + "_" + "SL-" + custcode + "-" + \
                                                   csv_list[i][3] + "-MT001"
                                    list1.append(secrule_name)
                            query = SecRule.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_secrule = [c for c in list1 if c not in list2]
                            print missing_secrule

                            action = "PERMIT"
                            for item in missing_secrule:
                                if 'tcp1-65535' in item:
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule

                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule
                                if 'tcp123' in item:
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule
                                if 'udp1-65535' in item:
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule

                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule
                                if 'udp123' in item:
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custname
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule
                                if 'tcp3389' in item:
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custcode + "-" + \
                                               csv_list[i][3] + "-OTD001"
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule

                                    dst_list = "seclist:" + "/Compute-" + authDomain + "/orchestration/SL-" + custcode + "-" + \
                                               csv_list[i][3] + "-MT001"
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-CustomerHosts001"
                                    csecrule = occ1.createsecrule(dst_list, item, src_list, secappln_name, action)
                                    print csecrule

                            secappln = ['tcp1-65535', 'tcp123', 'udp1-65535', 'udp123']
                            for secapp in secappln:
                                if secapp == 'tcp1-65535':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + seclist_name
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Qualys"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Qualys" + "_" + secapp + "_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + seclist_name
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + seclist_name
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][
                                                       4] + "001" + "_" + secapp + "_" + "SIL-Service-Domain"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                if secapp == 'tcp123':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + seclist_name
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][
                                                       4] + "001" + "_" + secapp + "_" + "SIL-public-internet-idd"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                if secapp == 'udp1-65535':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + seclist_name
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Qualys"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Qualys" + "_" + secapp + "_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seclist:" + seclist_name
                                    src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                    src_list = "seclist:" + seclist_name
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][
                                                       4] + "001" + "_" + secapp + "_" + "SIL-Service-Domain"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule
                                if secapp == 'udp123':
                                    secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                    dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                    src_list = "seclist:" + seclist_name
                                    secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                                   csv_list[i][3] + "-" + csv_list[i][
                                                       4] + "001" + "_" + secapp + "_" + "SIL-public-internet-idd"
                                    csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name,
                                                                  action)
                                    print csecrule

                            print "Creating Storage Volume"
                            fsize = str(csv_list[i][5])
                            size = fsize + "G"
                            properties = ["/oracle/public/storage/latency"]
                            bootable = "true"
                            imagelist = csv_list[i][2]
                            if imagelist == None:
                                imagelist = '/oracle/public/OL_6.8_UEKR3_x86_64'
                            name = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"
                            print "creating bootable colume"
                            bootvolume = occ1.createstoragevolume(size, properties, name, bootable, imagelist)
                            print bootvolume
                            nonbootsize = '64' + "G"
                            nonbootable = "false"
                            nonbootname = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"
                            print "creating non-bootable colume"
                            nonbootvolume = occ1.createnonboot(nonbootsize, properties, nonbootable, nonbootname)
                            print nonbootvolume

                            print "Creating an Orchestration"
                            relationships = []
                            account = "/Compute-" + authDomain + "/default"
                            name = "/Compute-" + authDomain + "/orchestration/" + custname + "-orch"
                            description = custname + " assembly"

                            label = custname
                            obj_type = "launchplan"
                            ha_policy = "active"

                            inst_name = "/Compute-" + authDomain + "/orchestration/" + custname
                            reverse_dns = True
                            placement_requirements = []
                            shape = csv_list[i][0]
                            if shape == None:
                                shape = 'oc3'
                            boot_order = [1]

                            index = 1
                            volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"

                            dataindex = 2
                            datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"

                            # sshkeys = "/Compute-" + authDomain + "/orchestration/" + custname + "-key"
                            sshkeys = "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT003-key"
                            tags = custname
                            networking_seclists = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + \
                                                  csv_list[i][3] + "-" + csv_list[i][4]
                            nat = "ipreservation:/Compute-" + authDomain + "/orchestration/" + hostlabel + '-eip'
                            dns = custname

                            corchestration = occ1.createorchestration(relationships, account, name, description, label,
                                                                      obj_type, ha_policy, inst_name, reverse_dns,
                                                                      placement_requirements, shape, instlabel,
                                                                      boot_order,
                                                                      index, volume, dataindex, datavol, sshkeys, tags,
                                                                      networking_seclists, nat)
                            print corchestration

                            print "----Strating Orchestration-----"
                            description = "Simple Orchestration"
                            uporch = occ1.updateorchestration(request, relationships, account, name, description, label,
                                                              obj_type, ha_policy, inst_name, reverse_dns,
                                                              placement_requirements, shape, imagelist, boot_order,
                                                              index, volume, dataindex, datavol, sshkeys, tags,
                                                              networking_seclists, nat)
                            print uporch

                elif network == 'ipbtn':
                    print "ip stuff"
                    for i in range(1, len(csv_list)):
                        usrname = listfetchall(list(Auth.objects.values_list('username').distinct()))
                        passwd = listfetchall(list(Auth.objects.values_list('password').distinct()))

                        occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
                        print occ1
                        cookies = occ1.login(user=usrname, password=passwd)
                        print cookies
                        if cookies == None:
                            pass
                        else:
                            print "Create a SSH key"
                            custname = authDomain.upper()
                            # hostlabel = 'EM2-Z17-DPEE2O-MT001'  # user input
                            hostlabel = csv_list[i][6] + "-" + csv_list[i][1] + "-" + csv_list[i][4] + "001"
                            parentpool = "/oracle/public/ippool"
                            permanent = True

                            fname = "/Compute-" + authDomain + "/orchestration/"
                            sname = os.path.join(fname, hostlabel)
                            # name = "/Compute-omcsops/orchestration/EM2-Z17-DPEE2O-MT001-eip"  # concatenate
                            kname = sname + '-eip'
                            crtipreserve = occ1.createipreserve(parentpool, permanent, kname)
                            print crtipreserve

                            # dir_name = '/tmp/documents'
                            # basepath = os.path.join(dir_name, csv_list[i][1])
                            # print basepath
                            # os.system('ssh-keygen -b 4096 -t rsa -N "" -C "" -f ' + basepath)
                            # li = os.listdir('/tmp/documents')
                            # f = open('/tmp/documents' + li[0], 'r')
                            # public_key = f.read()
                            # f = open('/tmp/documents' + li[1], 'r')
                            # private_key = f.read()
                            #
                            # enabled = True
                            # key = private_key
                            # name = sname + '-key'
                            # csshkey = occ1.createsshkey(enabled, key, name)
                            # print csshkey

                            print "Creating IP Network"
                            ipnetwork_name = "Net-NonProd-PvtMT01-AD1"
                            ipexchange = "OMCSEXCHANGE-01"
                            name = "/Compute-" + authDomain + "/orchestration/" + ipnetwork_name
                            ipAdressPrefix = "10.0.57.0/24"
                            ipNetworkExchange = "/Compute-" + authDomain + "/orchestration/" + ipexchange

                            cipnetwork = occ1.createipnetwork(name, ipAdressPrefix, ipNetworkExchange)
                            print cipnetwork

                            print "Creating an ACL"
                            list1 = ["/Compute-" + authDomain + "/orchestration/ACL-Prod-DB01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-Prod-PubMT01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-Prod-PvtMT01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-Prod-OTD01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-Prod-OTD02",
                                     "/Compute-" + authDomain + "/orchestration/ACL-NonProd-DB01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-NonProd-PubMT01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-NonProd-PvtMT01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-NonProd-OTD01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-PROD-PvtMT01-Net-AD1",
                                     "/Compute-" + authDomain + "/orchestration/ACL-PROD-PvtMT01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-Shared-Infra01",
                                     "/Compute-" + authDomain + "/orchestration/ACL-ALL"]
                            query = ACLs.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_acls = [c for c in list1 if c not in list2]
                            print missing_acls

                            for item in missing_acls:
                                cacl = occ1.createacl(item)
                                print cacl

                            print "----validating ipaddressprefixset----------"
                            list1 = ["/Compute-" + authDomain + "/orchestration/SIL-Bastion",
                                     "/Compute-" + authDomain + "/orchestration/SIL-ODEM",
                                     "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"]
                            query = IpAddrPrefixSets.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_ipaddressprefixset = [c for c in list1 if c not in list2]
                            print missing_ipaddressprefixset

                            if missing_ipaddressprefixset != []:
                                for item in missing_ipaddressprefixset:
                                    if "SIL-Bastion" in item:
                                        ipAddressPrefixes = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                             '143.47.209.32/27',
                                                             '141.145.31.32/27', '141.145.47.160/27', '160.34.5.64/27',
                                                             '129.152.34.32/27', '100.64.0.1/32']
                                    if "SIL-Service-Domain" in item:
                                        ipAddressPrefixes = ['160.34.9.221/32', '160.34.9.230/32', '160.34.9.222/32',
                                                             '160.34.9.234/32', '160.34.9.220/32',
                                                             '160.34.9.227/32', '160.34.9.161/32', '160.34.9.110/32',
                                                             '160.34.9.226/32', '160.34.9.228/32',
                                                             '160.34.9.224/32', '160.34.9.229/32', '160.34.9.235/32',
                                                             '160.34.9.175/32', '141.145.121.161/32',
                                                             '141.145.121.159/32', '141.145.121.148/32',
                                                             '141.145.121.153/32',
                                                             '141.145.121.155/32', '141.145.121.156/32',
                                                             '141.145.123.69/32', '141.145.123.68/32',
                                                             '141.145.121.142/32',
                                                             '141.145.121.160/32', '141.145.121.164/32',
                                                             '141.145.121.158/32', '141.145.121.157/32',
                                                             '141.145.121.50/32',
                                                             '140.86.49.110/32', '140.86.49.114/32',
                                                             '140.86.49.108/32', '140.86.49.90/32', '140.86.49.106/32',
                                                             '140.86.49.109/32', '140.86.49.112/32',
                                                             '140.86.49.107/32', '140.86.49.113/32', '140.86.49.111/32',
                                                             '140.86.51.117/32', '129.144.145.236/32',
                                                             '129.144.145.57/32', '129.144.145.174/32',
                                                             '129.144.145.226/32',
                                                             '129.144.145.9/32', '129.144.145.34/32',
                                                             '129.144.145.41/32', '129.144.145.61/32',
                                                             '129.144.145.227/32',
                                                             '129.144.145.75/32']
                                    if "SIL-ODEM" in item:
                                        ipAddressPrefixes = ['140.85.107.116/32', '140.85.107.117/32',
                                                             '140.85.107.118/32',
                                                             '141.146.185.0/25',
                                                             '141.146.185.160/27', '141.146.130.31/32',
                                                             '137.254.135.44/32']
                                    cipaddressprefixset = occ1.createipaddressprefixset(item, ipAddressPrefixes)
                                    print cipaddressprefixset

                            print "-----validating IPnetwork exchange------"
                            list1 = ["/Compute-" + authDomain + "/orchestration/OMCSEXCHANGE-01"]
                            query = IpNetworkExchange.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_ipnetworkexchange = [c for c in list1 if c not in list2]
                            print missing_ipnetworkexchange

                            for item in missing_ipnetworkexchange:
                                cipnetworkexchange = occ1.createipnetworkexchange(item)
                                print cipnetworkexchange

                            print "----validating secprotocols------"
                            list1 = ["/Compute-" + authDomain + "/orchestration/tcp1-65535",
                                     "/Compute-" + authDomain + "/orchestration/tcp22",
                                     "/Compute-" + authDomain + "/orchestration/tcp25",
                                     "/Compute-" + authDomain + "/orchestration/tcp53",
                                     "/Compute-" + authDomain + "/orchestration/tcp80",
                                     "/Compute-" + authDomain + "/orchestration/tcp111",
                                     "/Compute-" + authDomain + "/orchestration/tcp123",
                                     "/Compute-" + authDomain + "/orchestration/tcp143",
                                     "/Compute-" + authDomain + "/orchestration/tcp389",
                                     "/Compute-" + authDomain + "/orchestration/tcp443",
                                     "/Compute-" + authDomain + "/orchestration/tcp514",
                                     "/Compute-" + authDomain + "/orchestration/tcp515",
                                     "/Compute-" + authDomain + "/orchestration/tcp601",
                                     "/Compute-" + authDomain + "/orchestration/tcp631",
                                     "/Compute-" + authDomain + "/orchestration/tcp636",
                                     "/Compute-" + authDomain + "/orchestration/tcp1521-1522",
                                     "/Compute-" + authDomain + "/orchestration/tcp2049",
                                     "/Compute-" + authDomain + "/orchestration/tcp3128",
                                     "/Compute-" + authDomain + "/orchestration/tcp3389",
                                     "/Compute-" + authDomain + "/orchestration/tcp4000",
                                     "/Compute-" + authDomain + "/orchestration/tcp5986",
                                     "/Compute-" + authDomain + "/orchestration/tcp24345",
                                     "/Compute-" + authDomain + "/orchestration/tcp24346",
                                     "/Compute-" + authDomain + "/orchestration/tcp24347",
                                     "/Compute-" + authDomain + "/orchestration/udp53",
                                     "/Compute-" + authDomain + "/orchestration/udp111",
                                     "/Compute-" + authDomain + "/orchestration/udp123",
                                     "/Compute-" + authDomain + "/orchestration/udp514",
                                     "/Compute-" + authDomain + "/orchestration/udp601",
                                     "/Compute-" + authDomain + "/orchestration/udp515",
                                     "/Compute-" + authDomain + "/orchestration/udp631"]
                            query = SecProtocols.objects.values_list('name', flat=True).order_by('name')
                            list2 = []
                            for item in query:
                                a = str(item)
                                list2.append(a)
                            missing_secprotocols = [c for c in list1 if c not in list2]
                            print missing_secprotocols

                            for item in missing_secprotocols:
                                terminator = item.split('orchestration/')[1].strip()
                                ipProtocol = terminator[:3]
                                dstPortSet = [terminator[3:]]
                                description = "validated secprotocols"
                                csecprotocol = occ1.createsecprotocol(description, ipProtocol, dstPortSet, item)
                                print csecprotocol

                            # Code updation of VNICsets is pending
                            print "Create vnicset"
                            names = ['SL-Prod-DB01-Net-AD1', 'SL-Prod-PubMT01-Net-AD1', 'SL-Prod-PvtMT01-Net-AD1',
                                     'SL-Prod-OTD01-Net-AD1', 'SL-NonProd-DB01-Net-AD1',
                                     'SL-NonProd-PubMT01-Net-AD1', 'SL-NonProd-PvtMT01-Net-AD1',
                                     'SL-NonProd-OTD01-Net-AD1',
                                     'SL-Shared-Infra01-Net-AD1', 'SL-Prod-DB01',
                                     'SL-Prod-PubMT01', 'SL-Prod-PvtMT01', 'SL-Prod-OTD01', 'SL-NonProd-DB01',
                                     'SL-NonProd-PubMT01', 'SL-NonProd-PvtMT01', 'SL-NonProd-OTD01',
                                     'SL-Shared-Infra01']
                            acl1 = "ACL-NonProd-PubMT01"
                            acl2 = "ACL-NonProd-PvtMT01"
                            acl3 = "ACL-NonProd-OTD01"
                            acl4 = "ACL-Shared-Infra01"
                            acl = "ACL-ALL"
                            vnics = ["/Compute-" + authDomain + "/orchestration/" + custname + "_eth0"]
                            appliedAcls1 = ["/Compute-" + authDomain + "/orchestration/" + acl1]
                            appliedAcls2 = ["/Compute-" + authDomain + "/orchestration/" + acl2]
                            appliedAcls3 = ["/Compute-" + authDomain + "/orchestration/" + acl3]
                            appliedAcls4 = ["/Compute-" + authDomain + "/orchestration/" + acl4]
                            appliedAcls = ["/Compute-" + authDomain + "/orchestration/" + acl]
                            for fname in names:
                                name = "/Compute-" + authDomain + "/orchestration/" + fname
                                vnicset1 = occ1.createvnicset(name, vnics, appliedAcls1)
                                vnicset2 = occ1.createvnicset(name, vnics, appliedAcls2)
                                vnicset3 = occ1.createvnicset(name, vnics, appliedAcls3)
                                vnicset4 = occ1.createvnicset(name, vnics, appliedAcls4)
                                vnicset = occ1.createvnicset(name, vnics, appliedAcls)
                                print vnicset1
                                print vnicset2
                                print vnicset3
                                print vnicset4
                                print vnicset

                            print "Creating Storage Volume"
                            fsize = str(csv_list[i][5])
                            size = fsize + "G"
                            properties = ["/oracle/public/storage/latency"]
                            bootable = "true"
                            imagelist = csv_list[i][2]
                            if imagelist == None:
                                imagelist = '/oracle/public/OL_6.8_UEKR3_x86_64'
                            name = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"
                            print "creating bootable colume"
                            bootvolume = occ1.createstoragevolume(size, properties, name, bootable, imagelist)
                            print bootvolume
                            nonbootsize = '64' + "G"
                            nonbootable = "false"
                            nonbootname = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"
                            print "creating non-bootable colume"
                            nonbootvolume = occ1.createnonboot(nonbootsize, properties, nonbootable, nonbootname)
                            print nonbootvolume

                            print "Creating an IP Network Orchestration"
                            relationships = []
                            account = "/Compute-" + authDomain + "/default"
                            name = "/Compute-" + authDomain + "/orchestration/" + custname + "-orch"
                            description = custname + " assembly"

                            label = custname
                            obj_type = "launchplan"
                            ha_policy = "active"

                            inst_name = "/Compute-" + authDomain + "/orchestration/" + custname
                            reverse_dns = True
                            placement_requirements = []
                            shape = csv_list[i][0]
                            if shape == None:
                                shape = 'oc3'
                            boot_order = [1]

                            index = 1
                            volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"

                            dataindex = 2
                            datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"

                            sshkeys = "/Compute-omcsservicedom1/girish.ahuja@oracle.com/ahuja"
                            tags = custname

                            vnic = "/Compute-" + authDomain + "/orchestration/" + custname + "_eth0"
                            # vnic = "/Compute-" + authDomain + "/orchestration/INFRA-TEST-MT02_eth0"
                            is_default_gateway = True
                            networking_nat = "network/v1/ipreservation:/Compute-" + authDomain + "/orchestration/" + hostlabel + "-eip"
                            vnicsets = []
                            # for fname in names:
                            #     vnicsets = ["/Compute-" + authDomain + "/orchestration/" + fname]
                            vnicsets = ["/Compute-" + authDomain + "/orchestration/" + "SL-NonProd-PvtMT01-Net-AD1",
                                        "/Compute-" + authDomain + "/orchestration/" + "SL-NonProd-PvtMT01"]
                            ipnetwork = "/Compute-" + authDomain + "/orchestration/" + ipnetwork_name
                            dns = custname

                            corchestration = occ1.createiporchestration(relationships, account, name, description,
                                                                        label,
                                                                        obj_type, ha_policy, inst_name, reverse_dns,
                                                                        placement_requirements, shape, instlabel,
                                                                        boot_order, index, volume, dataindex, datavol,
                                                                        sshkeys, tags, vnic, is_default_gateway,
                                                                        networking_nat, vnicsets, ipnetwork)
                            print corchestration

                            print "-----starting orchestration-----"
                            description = "Simple Orchestration"
                            uporch = occ1.updateiporchestration(relationships, account, name, description, label,
                                                                obj_type, ha_policy, inst_name, reverse_dns,
                                                                placement_requirements, shape, imagelist,
                                                                boot_order, index, volume, dataindex, datavol,
                                                                sshkeys, tags, vnic, is_default_gateway,
                                                                networking_nat, vnicsets, ipnetwork)
                            print uporch



            if 'orchstnbtn' in request.POST:
                for i in range(1, len(csv_list)):
                    usrname = listfetchall(list(Auth.objects.values_list('username').distinct()))
                    passwd = listfetchall(list(Auth.objects.values_list('password').distinct()))

                    occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
                    print occ1
                    cookies = occ1.login(user=usrname, password=passwd)
                    print cookies
                    if cookies == None:
                        pass
                    else:
                        print "Create a SSH key"
                        #hostlabel = 'EM2-Z17-DPEE2O-MT001'  # user input
                        hostlabel = csv_list[i][6]+"-"+csv_list[i][1]+"-"+csv_list[i][4]+"001"
                        parentpool = "/oracle/public/ippool"
                        permanent = True

                        fname = "/Compute-" + authDomain + "/orchestration/"
                        sname = os.path.join(fname, hostlabel)
                        # name = "/Compute-omcsops/orchestration/EM2-Z17-DPEE2O-MT001-eip"  # concatenate
                        kname = sname + '-eip'
                        crtipreserve = occ1.createipreserve(parentpool, permanent, kname)
                        print crtipreserve

                        # dir_name = '/home/opc/sshdir'
                        # basepath = os.path.join(dir_name, csv_list[i][1])
                        # print basepath
                        # os.system('ssh-keygen -b 4096 -t rsa -N "" -C "" -f ' + basepath)
                        # li = os.listdir('/tmp/sshdir')
                        # f = open('/home/opc/sshdir' + li[0], 'r')
                        # public_key = f.read()
                        # f = open('/home/opc/sshdir' + li[1], 'r')
                        # private_key = f.read()

                        bits = 4096
                        new_key = RSA.generate(bits, e=65537)
                        public_key = new_key.publickey().exportKey("OpenSSH")
                        print public_key

                        enabled = True
                        key = private_key
                        name = sname + '-key'
                        csshkey = occ1.createsshkey(enabled, key, name)
                        print csshkey

                        print "Creating Seclist"
                        custname = authDomain.upper()
                        policy = "DENY"
                        outbound_cidr_policy = "REJECT"
                        seclist_name = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + csv_list[i][3] + "-" + csv_list[i][4]
                        cseclist = occ1.createseclist(policy, outbound_cidr_policy, seclist_name)
                        print cseclist

                        print "Creating Secappln"
                        protocols = ['tcp', 'udp']
                        ports = ['1-65535', '22', '25', '53', '80', '111', '123', '389', '443', '514', '601', '636',
                                 '2049',
                                 '3128', '3389', '5986', '24345', '24346', '24347']
                        for port in ports:
                            if port == '1-65535' or '53' or '111' or '123' or '514' or '601':
                                protocol = 'udp'
                                secappln = protocol + port
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                print csecappln
                            if port == '1-65535' or '22' or '25' or '53' or '80' or '111' or '123' or '389' or '443' or '514' or '601' or '636' or '2049' or '3128' or '3389' or '5986' or '24345' or '24346' or '24347':
                                protocol = 'tcp'
                                secappln = protocol + port
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secappln
                                csecappln = occ1.createsecappln(protocol, port, secappln_name)
                                print csecappln

                        print "Creating Seciplist"
                        secipentries = []
                        names = ['SIL-public-internet-idd', 'SIL-Bastion', 'SIL-CustomerHosts001', 'SIL-OCNA',
                                 'SIL-OMCS-Infrastructure', 'SIL-OPC-StorageCloud', 'SIL-Service-Domain', 'SIL-Qualys']
                        for name in names:
                            if name == 'SIL-public-internet-idd':
                                secipentries = ['0.0.0.0/0']
                            if name == 'SIL-Bastion':
                                secipentries = ['160.34.57.0/27', '129.91.63.128/27', '129.91.15.160/27',
                                                '143.47.209.32/27', '141.145.31.32/27',
                                                '141.145.47.160/27', '160.34.5.64/27', '129.152.34.32/27',
                                                '100.64.0.1/32']
                            if name == 'SIL-CustomerHosts001':
                                secipentries = ['140.84.230.200/32']
                            if name == 'SIL-OCNA':
                                secipentries = ['137.254.4.0/27', '148.87.19.192/27', '143.47.214.0/23',
                                                '160.34.87.0/24',
                                                '160.34.88.0/23',
                                                '160.34.91.0/24', '160.34.92.0/23', '160.34.108.0/24',
                                                '160.34.109.0/24',
                                                '160.34.110.0/24',
                                                '160.34.111.0/24', '160.34.113.0/24', '160.34.115.0/24',
                                                '160.34.117.0/24',
                                                '160.34.121.0/24',
                                                '160.34.126.0/23', '160.34.5.64/27']
                            if name == 'SIL-OMCS-Infrastructure':
                                secipentries = ['148.87.235.208/29', '10.154.222.0/23', '10.154.224.0/23',
                                                '10.231.229.24/29', '129.155.244.128/29',
                                                '129.155.244.144/28', '137.254.128.13/32', '137.254.129.32/28',
                                                '137.254.129.48/29', '137.254.135.40/29',
                                                '137.254.184.0/21', '140.83.230.0/28', '140.83.230.64/26',
                                                '140.85.0.0/16',
                                                '141.146.128.12/32',
                                                '141.146.129.152/29', '141.146.129.160/29', '141.146.130.0/25',
                                                '141.146.130.128/27', '141.146.131.120/29',
                                                '141.146.154.0/23', '141.146.156.0/24', '141.146.158.0/24',
                                                '141.146.159.64/26', '141.146.159.128/25',
                                                '141.146.185.0/24', '141.146.190.0/28', '141.146.200.16/28',
                                                '141.146.226.0/23', '141.146.232.0/21', '144.20.7.32/28',
                                                '144.20.7.112/29', '144.20.12.136/29', '144.20.27.64/29',
                                                '144.20.30.0/23',
                                                '144.20.48.48/28', '144.20.48.64/27',
                                                '144.20.48.112/28', '144.20.48.128/27', '144.20.49.24/29',
                                                '144.20.49.128/29', '144.20.50.0/23', '144.20.52.0/29',
                                                '144.20.52.40/29', '144.20.52.48/29', '144.20.52.88/29',
                                                '144.20.52.96/29',
                                                '144.20.52.136/29', '144.20.52.144/29',
                                                '144.20.52.192/28', '144.20.55.32/28', '144.20.55.240/28',
                                                '144.20.59.48/28', '144.20.59.104/29', '144.20.59.112/29',
                                                '144.20.59.152/29', '144.20.59.160/29', '144.20.59.200/29',
                                                '144.20.59.208/29', '144.20.59.248/29', '144.20.63.0/28',
                                                '144.20.63.32/27', '144.20.63.128/27', '144.20.63.192/29',
                                                '144.20.63.208/28', '144.20.83.48/29', '144.20.83.144/29',
                                                '144.20.98.0/25', '144.20.99.64/26', '144.20.108.248/29',
                                                '144.20.116.0/26',
                                                '144.20.191.80/28', '144.20.227.0/24', '141.146.128.0/17',
                                                '10.224.0.0/14',
                                                '100.64.1.1/29', '100.64.1.16/29']
                            if name == 'SIL-OPC-StorageCloud':
                                secipentries = ['129.152.32.0/23', '160.34.0.0/23', '160.34.2.0/23', '160.34.5.0/27',
                                                '160.34.14.32/27', '129.152.172.0/23']
                            if name == 'SIL-Service-Domain':
                                secipentries = ['160.34.9.221', '160.34.9.230', '160.34.9.222', '160.34.9.234',
                                                '160.34.9.220', '160.34.9.227', '160.34.9.161',
                                                '160.34.9.110', '160.34.9.226', '160.34.9.228', '160.34.9.224',
                                                '160.34.9.229', '160.34.9.235', '160.34.9.175',
                                                '141.145.121.161', '141.145.121.159', '141.145.121.148',
                                                '141.145.121.153',
                                                '141.145.121.155', '141.145.121.156',
                                                '141.145.123.69', '141.145.123.68', '141.145.121.142',
                                                '141.145.121.160',
                                                '141.145.121.164', '141.145.121.158',
                                                '141.145.121.157', '141.145.121.50', '140.86.49.110', '140.86.49.114',
                                                '140.86.49.108', '140.86.49.90',
                                                '140.86.49.106', '140.86.49.109', '140.86.49.112', '140.86.49.107',
                                                '140.86.49.113', '140.86.49.111', '140.86.51.117',
                                                '129.144.145.236', '129.144.145.57', '129.144.145.174',
                                                '129.144.145.226',
                                                '129.144.145.9', '129.144.145.34', '129.144.145.41', '129.144.145.61',
                                                '129.144.145.227', '129.144.145.75']
                            if name == 'SIL-Qualys':
                                secipentries = ['207.238.80.72/32', '207.238.80.73/32', '207.238.80.74/32',
                                                '207.238.80.75/32', '207.238.80.76/32']
                            secip_name = "/Compute-" + authDomain + "/orchestration/" + name
                            cseciplist = occ1.createseciplist(secip_name, secipentries)
                            print cseciplist

                        print "Creating Secrule"
                        action = "PERMIT"
                        secappln = ['tcp1-65535', 'tcp123', 'udp1-65535', 'udp123']
                        for secapp in secappln:
                            if secapp == 'tcp1-65535':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + seclist_name
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Qualys"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Qualys" + "_" + secapp + "_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + seclist_name
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                src_list = "seclist:" + seclist_name
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][
                                                   4] + "001" + "_" + secapp + "_" + "SIL-Service-Domain"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                            if secapp == 'tcp123':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                src_list = "seclist:" + seclist_name
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][
                                                   4] + "001" + "_" + secapp + "_" + "SIL-public-internet-idd"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                            if secapp == 'udp1-65535':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + seclist_name
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Qualys"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Qualys" + "_" + secapp + "_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seclist:" + seclist_name
                                src_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Bastion"
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + "SIL-Bastion" + "_" + secapp + "_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][4] + "001"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-Service-Domain"
                                src_list = "seclist:" + seclist_name
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][
                                                   4] + "001" + "_" + secapp + "_" + "SIL-Service-Domain"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule
                            if secapp == 'udp123':
                                secappln_name = "/Compute-" + authDomain + "/orchestration/" + secapp
                                dst_list = "seciplist:" + "/Compute-" + authDomain + "/orchestration/SIL-public-internet-idd"
                                src_list = "seclist:" + seclist_name
                                secrule_name = "/Compute-" + authDomain + "/orchestration/Rule_" + custname + "-" + \
                                               csv_list[i][3] + "-" + csv_list[i][
                                                   4] + "001" + "_" + secapp + "_" + "SIL-public-internet-idd"
                                csecrule = occ1.createsecrule(dst_list, secrule_name, src_list, secappln_name, action)
                                print csecrule

                        print "Creating Storage Volume"
                        fsize = str(csv_list[i][5])
                        size = fsize + "G"
                        properties = ["/oracle/public/storage/latency"]
                        bootable = "true"
                        imagelist = csv_list[i][2]
                        if imagelist == None:
                            imagelist = '/oracle/public/OL_6.8_UEKR3_x86_64'
                        name = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"
                        print "creating bootable colume"
                        bootvolume = occ1.createstoragevolume(size, properties, name, bootable, imagelist)
                        print bootvolume
                        nonbootsize = '64' + "G"
                        nonbootable = "false"
                        nonbootname = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"
                        print "creating non-bootable colume"
                        nonbootvolume = occ1.createnonboot(nonbootsize, properties, nonbootable, nonbootname)
                        print nonbootvolume

                        print "Creating an Orchestration"
                        relationships = []
                        account = "/Compute-" + authDomain + "/default"
                        name = "/Compute-" + authDomain + "/orchestration/" + custname + "-orch"
                        description = custname + " assembly"

                        label = custname
                        obj_type = "launchplan"
                        ha_policy = "active"

                        inst_name = "/Compute-" + authDomain + "/orchestration/" + custname
                        reverse_dns = True
                        placement_requirements = []
                        shape = csv_list[i][0]
                        if shape == None:
                            shape = 'oc3'
                        boot_order = [1]

                        index = 1
                        volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"

                        dataindex = 2
                        datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"

                        #sshkeys = "/Compute-" + authDomain + "/orchestration/" + custname + "-key"
                        sshkeys = "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT003-key"
                        tags = custname
                        networking_seclists = "/Compute-" + authDomain + "/orchestration/SL-" + custname + "-" + csv_list[i][3] + "-" + csv_list[i][4]
                        nat = "ipreservation:/Compute-" + authDomain + "/orchestration/" + hostlabel + '-eip'
                        dns = custname

                        corchestration = occ1.createorchestration(relationships, account, name, description, label,
                                                                  obj_type, ha_policy, inst_name, reverse_dns,
                                                                  placement_requirements, shape, instlabel, boot_order,
                                                                  index, volume,dataindex,datavol, sshkeys, tags,
                                                                  networking_seclists, nat)
                        print corchestration

                        print "----Strating Orchestration-----"
                        description = "Simple Orchestration"
                        uporch = occ1.updateorchestration(request,relationships, account, name, description, label,
                                                          obj_type, ha_policy,inst_name,reverse_dns,
                                                          placement_requirements,shape,imagelist,boot_order,
                                                          index, volume, dataindex, datavol, sshkeys, tags,
                                                          networking_seclists, nat)
                        print uporch

            elif 'ipbtn' in request.POST:
                print "-------IPnetworking part--------------"
                for i in range(1, len(csv_list)):
                    usrname = listfetchall(list(Auth.objects.values_list('username').distinct()))
                    passwd = listfetchall(list(Auth.objects.values_list('password').distinct()))

                    occ1 = OracleComputeCloud(endPointUrl=url, authenticationDomain=authDomain)
                    print occ1
                    cookies = occ1.login(user=usrname, password=passwd)
                    print cookies
                    if cookies == None:
                        pass
                    else:
                        print "Create a SSH key"
                        custname = authDomain.upper()
                        # hostlabel = 'EM2-Z17-DPEE2O-MT001'  # user input
                        hostlabel = csv_list[i][6] + "-" + csv_list[i][1] + "-" + csv_list[i][4] + "001"
                        parentpool = "/oracle/public/ippool"
                        permanent = True

                        fname = "/Compute-" + authDomain + "/orchestration/"
                        sname = os.path.join(fname, hostlabel)
                        # name = "/Compute-omcsops/orchestration/EM2-Z17-DPEE2O-MT001-eip"  # concatenate
                        kname = sname + '-eip'
                        crtipreserve = occ1.createipreserve(parentpool, permanent, kname)
                        print crtipreserve

                        # dir_name = '/tmp/documents'
                        # basepath = os.path.join(dir_name, csv_list[i][1])
                        # print basepath
                        # os.system('ssh-keygen -b 4096 -t rsa -N "" -C "" -f ' + basepath)
                        # li = os.listdir('/tmp/documents')
                        # f = open('/tmp/documents' + li[0], 'r')
                        # public_key = f.read()
                        # f = open('/tmp/documents' + li[1], 'r')
                        # private_key = f.read()
                        #
                        # enabled = True
                        # key = private_key
                        # name = sname + '-key'
                        # csshkey = occ1.createsshkey(enabled, key, name)
                        # print csshkey

                        print "Creating IP Network"
                        ipnetwork_name = "Net-NonProd-PvtMT01-AD1"
                        ipexchange = "OMCSEXCHANGE-01"
                        name = "/Compute-" + authDomain + "/orchestration/" + ipnetwork_name
                        ipAdressPrefix = "10.0.57.0/24"
                        ipNetworkExchange = "/Compute-" + authDomain + "/orchestration/" + ipexchange

                        cipnetwork = occ1.createipnetwork(name, ipAdressPrefix, ipNetworkExchange)
                        print cipnetwork

                        print "Creating an ACL"
                        acl_name = ['ACL-NonProd-PubMT01', 'ACL-NonProd-PvtMT01', 'ACL-NonProd-OTD01',
                                    'ACL-Shared-Infra01',
                                    'ACL-ALL']
                        for acl in acl_name:
                            name = "/Compute-" + authDomain + "/orchestration/" + acl
                            cacl = occ1.createacl(name)
                            print cacl

                        print "Create ipaddressprefixset"
                        ipaddressprefixset_name = 'SIL-EM'
                        name = "/Compute-" + authDomain + "/orchestration/" + ipaddressprefixset_name
                        ipAddressPrefixes = ['141.146.185.0/25', '140.85.107.96/27']
                        cipaddressprefixset = occ1.createipaddressprefixset(name, ipAddressPrefixes)
                        print cipaddressprefixset

                        print "Create IPnetwork Ipreservation"

                        name = "/Compute-" + authDomain + "/orchestration/" + hostlabel + "-eip"
                        ipAddressPool = "/oracle/public/public-ippool"
                        cipnetworkipreservation = occ1.createipnetworkipreservation(name, ipAddressPool)
                        print cipnetworkipreservation

                        print "Create IPnetwork exchange"
                        name = "/Compute-" + authDomain + "/orchestration/" + ipexchange
                        cipnetworkexchange = occ1.createipnetworkexchange(name)
                        print cipnetworkexchange

                        print "Create Prefixdestinationsecrule"
                        secprotocols = 'tcp22'
                        destinationipaddressprefixes = 'SIL-EM'
                        dstacl = 'ACL-ALL'
                        name = "/Compute-" + authDomain + "/orchestration/Rule_" + dstacl + "_" + secprotocols + "_" + destinationipaddressprefixes
                        flowdirection = 'egress'
                        acl = "/Compute-" + authDomain + "/orchestration/" + dstacl
                        secProtocols = "/Compute-" + authDomain + "/orchestration/" + secprotocols
                        dstIpAddressPrefixSets = "/Compute-" + authDomain + "/orchestration/" + destinationipaddressprefixes
                        cprefixdestinationsecrule = occ1.createprefixdestinatiosecrule(name, flowdirection, acl, secProtocols, dstIpAddressPrefixSets)
                        print cprefixdestinationsecrule

                        print "Create Prefixsourcesecrule"
                        srcipaddressprefixes = 'SIL-EM'
                        srcacl = 'ACL-ALL'
                        name = "/Compute-" + authDomain + "/orchestration/Rule_" + srcipaddressprefixes + "_" + secprotocols + "_" + srcacl
                        flowdirection = 'ingress'
                        acl = "/Compute-" + authDomain + "/orchestration/" + srcacl
                        secProtocols = "/Compute-" + authDomain + "/orchestration/" + secprotocols
                        srcipaddressprefixSets = "/Compute-" + authDomain + "/orchestration/" + srcipaddressprefixes
                        cprefixsourcesecrule = occ1.createprefixsoucesecrule(name, flowdirection, acl, secProtocols,srcipaddressprefixSets)
                        print cprefixsourcesecrule

                        print "Create secprotocol"
                        description = "Sample Security protocol"
                        ipProtocol = 'tcp'
                        dstPortSet = ['22']
                        name = "/Compute-" + authDomain + "/orchestration/" + ipProtocol + '22'
                        csecprotocol = occ1.createsecprotocol(description, ipProtocol, dstPortSet, name)
                        print csecprotocol

                        print "Create vnicset"
                        names = ['SL-Prod-DB01-Net-AD1', 'SL-Prod-PubMT01-Net-AD1', 'SL-Prod-PvtMT01-Net-AD1',
                                 'SL-Prod-OTD01-Net-AD1', 'SL-NonProd-DB01-Net-AD1',
                                 'SL-NonProd-PubMT01-Net-AD1', 'SL-NonProd-PvtMT01-Net-AD1',
                                 'SL-NonProd-OTD01-Net-AD1',
                                 'SL-Shared-Infra01-Net-AD1', 'SL-Prod-DB01',
                                 'SL-Prod-PubMT01', 'SL-Prod-PvtMT01', 'SL-Prod-OTD01', 'SL-NonProd-DB01',
                                 'SL-NonProd-PubMT01', 'SL-NonProd-PvtMT01', 'SL-NonProd-OTD01',
                                 'SL-Shared-Infra01']
                        acl1 = "ACL-NonProd-PubMT01"
                        acl2 = "ACL-NonProd-PvtMT01"
                        acl3 = "ACL-NonProd-OTD01"
                        acl4 = "ACL-Shared-Infra01"
                        acl = "ACL-ALL"
                        vnics = ["/Compute-" + authDomain + "/orchestration/" + custname + "_eth0"]
                        appliedAcls1 = ["/Compute-" + authDomain + "/orchestration/" + acl1]
                        appliedAcls2 = ["/Compute-" + authDomain + "/orchestration/" + acl2]
                        appliedAcls3 = ["/Compute-" + authDomain + "/orchestration/" + acl3]
                        appliedAcls4 = ["/Compute-" + authDomain + "/orchestration/" + acl4]
                        appliedAcls = ["/Compute-" + authDomain + "/orchestration/" + acl]
                        for fname in names:
                            name = "/Compute-" + authDomain + "/orchestration/" + fname
                            vnicset1 = occ1.createvnicset(name, vnics, appliedAcls1)
                            vnicset2 = occ1.createvnicset(name, vnics, appliedAcls2)
                            vnicset3 = occ1.createvnicset(name, vnics, appliedAcls3)
                            vnicset4 = occ1.createvnicset(name, vnics, appliedAcls4)
                            vnicset = occ1.createvnicset(name, vnics, appliedAcls)
                            print vnicset1
                            print vnicset2
                            print vnicset3
                            print vnicset4
                            print vnicset

                        print "Creating Storage Volume"
                        fsize = str(csv_list[i][5])
                        size = fsize + "G"
                        properties = ["/oracle/public/storage/latency"]
                        bootable = "true"
                        imagelist = csv_list[i][2]
                        if imagelist == None:
                            imagelist = '/oracle/public/OL_6.8_UEKR3_x86_64'
                        name = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"
                        cstoragevolume = occ1.createstoragevolume(size, properties, name, bootable, imagelist)
                        print cstoragevolume
                        nonbootsize = '64' + "G"
                        nonbootable = "false"
                        nonbootname = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"
                        nonbootvolume = occ1.createnonboot(nonbootsize, properties, nonbootable, nonbootname)
                        print nonbootvolume

                        print "Creating an IP Network Orchestration"
                        relationships = []
                        account = "/Compute-" + authDomain + "/default"
                        name = "/Compute-" + authDomain + "/orchestration/" + custname + "-orch"
                        description = custname + " assembly"

                        label = custname
                        obj_type = "launchplan"
                        ha_policy = "active"

                        inst_name = "/Compute-" + authDomain + "/orchestration/" + custname
                        reverse_dns = True
                        placement_requirements = []
                        shape = csv_list[i][0]
                        if shape == None:
                            shape = 'oc3'
                        boot_order = [1]

                        index = 1
                        volume = "/Compute-" + authDomain + "/orchestration/" + custname + "-boot"

                        dataindex = 2
                        datavol = "/Compute-" + authDomain + "/orchestration/" + custname + "-data01"

                        sshkeys = "/Compute-omcsservicedom1/girish.ahuja@oracle.com/ahuja"
                        tags = custname

                        vnic = "/Compute-" + authDomain + "/orchestration/" + custname + "_eth0"
                        #vnic = "/Compute-" + authDomain + "/orchestration/INFRA-TEST-MT02_eth0"
                        is_default_gateway = True
                        networking_nat = "network/v1/ipreservation:/Compute-" + authDomain + "/orchestration/" + hostlabel + "-eip"
                        vnicsets = []
                        # for fname in names:
                        #     vnicsets = ["/Compute-" + authDomain + "/orchestration/" + fname]
                        vnicsets = ["/Compute-" + authDomain + "/orchestration/" + "SL-NonProd-PvtMT01-Net-AD1", "/Compute-" + authDomain + "/orchestration/" + "SL-NonProd-PvtMT01"]
                        ipnetwork = "/Compute-" + authDomain + "/orchestration/" + ipnetwork_name
                        dns = custname

                        corchestration = occ1.createiporchestration(relationships, account, name, description, label,
                                                                    obj_type, ha_policy, inst_name, reverse_dns,
                                                                    placement_requirements, shape, instlabel,
                                                                    boot_order,index, volume, dataindex, datavol,
                                                                    sshkeys, tags,vnic, is_default_gateway,
                                                                    networking_nat, vnicsets,ipnetwork)
                        print corchestration

                        print "-----starting orchestration-----"
                        description = "Simple Orchestration"
                        uporch = occ1.updateiporchestration(relationships, account, name, description, label,
                                                            obj_type, ha_policy, inst_name,reverse_dns,
                                                            placement_requirements, shape, imagelist,
                                                            boot_order,index, volume, dataindex, datavol,
                                                            sshkeys, tags, vnic, is_default_gateway,
                                                            networking_nat, vnicsets,ipnetwork)
                        print uporch

                        connection = MySQLdb.connect("omcsbabsbvhnre", "praj", "", "prov")
                        cursord = connection.cursor()
                        # creating views
                        sql_view1 = "CREATE OR REPLACE VIEW shared_ip as SELECT p1.private_ip,p2.public_ip,p1.shape,p2.name,p1.state,p1.platform,p1.user FROM instances as p1 INNER JOIN ipreserve as p2 on p2.name LIKE CONCAT('%',p1.label , '%');"
                        cursord.execute(sql_view1)

                        sql_view2 = "CREATE OR REPLACE VIEW shared_ip_nw as SELECT p1.private_ip,p1.public_ip,p1.shape,p1.name,p1.state,p2.ram,p1.platform,p2.user FROM shared_ip as p1 INNER JOIN shape as p2 on p1.shape = p2.shape_name;"
                        cursord.execute(sql_view2)

                        connection.commit()
                        cursord.close()  # closing connection


            # for i in range(len(data)):
            #     shape = Shapes.objects.values('shape_name') # Getting all shape_name from database
            #     list_shape = [entry for entry in shape]
            #     valshape = map(lambda x: (x['shape_name']), list_shape) # Data purification
            #     if data[i][0] in valshape:              # validating shape
            #         fshape.append(data[i][0])           # append the data to list
            #         fauthDomain.append(authDomain)      # append domain,url,dccode,custcode,account
            #         furl.append(url)
            #         fstorage.append(storage)
            #         fdccode.append(dccode)
            #         fcustcode.append(custcode)
            #         faccount.append(account)
            #         connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
            #         cursord = connection.cursor()
            #         cursord.execute('''select private_ip from shared_ip_nw where shape="%s";''' % (data[i][0]))  # Retrieving all Source dropdown list
            #         private = dictfetchall(cursord)
            #         private_ip = map(lambda x: (x['private_ip']), private)
            #         cursord.execute('''select public_ip from shared_ip_nw where shape="%s";''' % (data[i][0]))  # Retrieving all Source dropdown list
            #         public = dictfetchall(cursord)
            #         public_ip = map(lambda x: (x['public_ip']), public)
            #         cursord.execute('''select platform from shared_ip_nw where shape="%s";''' % (data[i][0]))  # Retrieving all Source dropdown list
            #         platforms = dictfetchall(cursord)
            #         platform = map(lambda x: (x['platform']), platforms)
            #         fprivate.append(private_ip)
            #         fpublic.append(public_ip)
            #         fplatform.append(platform)
            #         shapeflag =1                        # setting shape flag
            #
            #     datavolsize = data[i][1]
            #     if isinstance(datavolsize, float) == True:  # validating datavolsize
            #         fdatavolsize.append(data[i][1])         # append the data to list
            #         datavolflag = 1                     # setting datavolflag
            #
            #
            #     appinstance = data[i][2]                # validating appinstance
            #     if isinstance(appinstance, unicode) == True and shapeflag == 1 and datavolflag == 1:
            #         fappinstance.append(data[i][2])     # append the data to list
            #         appinstanceflag = 1                 # setting appinstanceflag
            #
            #
            #     tier = Tier.objects.values('tier_name') # Getting all tier_name from database
            #     list_tier = [entry for entry in tier]
            #     valtier = map(lambda x: (x['tier_name']), list_tier)    # data purification
            #     if data[i][3] in valtier:               # validating tier
            #         ftier.append(data[i][3])            # append the data to list
            #         tierflag = 1                        # setting tierflag
            #
            #     instance = Instance.objects.values('inst_name') # Getting all instance_name from database
            #     list_instance = [entry for entry in instance]
            #     valinstance = map(lambda x: (x['inst_name']), list_instance)    # data purification
            #     if data[i][4] in valinstance:           # validating tier
            #         finstance.append(data[i][4])        # append the data to list
            #         instanceflag = 1                    # setting instanceflag
            #
            #     image = Image.objects.values('image_name')  # Getting all image_name from database
            #     list_image = [entry for entry in image]
            #     valimage = map(lambda x: (x['image_name']), list_image) # data purification
            #     if data[i][6] in valimage:              # validating tier
            #         fimage.append(data[i][6])           # append the data to list
            #         imageflag = 1                       # setting imageflag
            #         if "Microsoft" in fimage[-1]:       # whether the image is of the type "Microsoft"....!!
            #             p = list(Shapes.objects.values_list('ram').filter(shape_name=fshape[-1]))
            #             q = str(p).strip('[]')          # Getting all ram size matching shape from database
            #             r = str(q).strip('()')
            #             s = r[:-1]
            #             t = s[1:]
            #             u = t[:-1]
            #             rams = u[1:]
            #             ramint = int(rams)
            #             ram = ramint / 1024             # calculating ram
            #             pagevolsize = (ram * 1.5) + 1   # calculating pagevolumesize
            #             fpagevolsize.append(pagevolsize)    # appending pagevolumesize to the list
            #             emvolsize = 10                  # static emvolsize
            #             femvolsize.append(emvolsize)    # appending emvolumesize to the list
            #             datacenter = url[24:27]         # datacenter for Microfoft image
            #             fdatacenter.append(datacenter)  # appending emvolumesize to the list
            #             size = '64'                     # OS Size for Microsoft image
            #             fsize.append(size)              # appending size to the list
            #             sizeno = int(size)
            #             datavol = int(datavolsize)      # Calculating footprint
            #             footprint = sizeno + datavol
            #             backupvolsize = footprint * 1.5 # Calculating backupvolumesize
            #             fbackupvolsize.append(backupvolsize)    # appending backupvolumesize to the list
            #             region = url[24:27].upper()             # Derived Region from API
            #             zone = url[12:15].upper()               # Derived Zone from API
            #             hostlabel = '%s-%s-%s-%s001' % (region,zone,appinstance, finstance[-1]) # Calculating hostlabel
            #             fhostlabel.append(hostlabel)            # appending hostlabel to the list
            #             seclist = 'SL-%s-%s-%s-001' % (custcode, ftier[-1], finstance[-1])  # Calculating seclist
            #             fseclist.append(seclist)                # appending seclist to the list
            #         else:
            #             pagevolsize = None              # Pagevolume is 'None for Linux image
            #             fpagevolsize.append(pagevolsize) # appending pagecolumesize to the list
            #             emvolsize = None                # emvolume is 'None for Linux image
            #             femvolsize.append(emvolsize)     # appending emcolumesize to the list
            #             datacenter = None               # datacenter is 'None for Linux image
            #             fdatacenter.append(datacenter)  # appending datacenter to the list
            #             size = '32'                     # OS Size for Linux image
            #             fsize.append(size)              # appending size to the list
            #             sizeno = int(size)
            #             datavol = int(datavolsize)
            #             footprint = sizeno + datavol    # Calculating footprint
            #             backupvolsize = footprint * 1.5 # Calculating backupvolumesize
            #             fbackupvolsize.append(backupvolsize)    # appending backupvolumesize to the list
            #             region = url[24:27].upper()     # Derived Region from API
            #             zone = url[12:15].upper()       # Derived Zone from API
            #             hostlabel = '%s-%s-%s-%s001' % (region, zone, appinstance, finstance[-1])   # Calculating hostlabel
            #             fhostlabel.append(hostlabel)    # appending hostlabel to the list
            #             seclist = 'SL-%s-%s-%s-001' % (custcode, ftier[-1], finstance[-1])  # Calculating seclist
            #             fseclist.append(seclist)        # appending seclist to the list
            #
            #     ssh = SSHkeys.objects.values('ssh_name')    # Getting all ssh_name from database
            #     list_ssh = [entry for entry in ssh]
            #     valssh = map(lambda x: (x['ssh_name']), list_ssh)   # data purification
            #     if data[i][5] in valssh:                    # validating ssh
            #         fssh.append(data[i][5])                 # append the data to list
            #         sshflag = 1                             # setting sshflag
            #
            #     if data[i][0] in valshape and data[i][5] in valssh:
            #         p = list(Instances.objects.values_list('private_ip').filter(shape__contains=data[i][0], sshkeys__contains=data[i][5]))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         private_ip = u[1:]
            #
            #
            #         p = list(Instances.objects.values_list('custname').filter(shape__contains=data[i][0],
            #                                                                     sshkeys__contains=data[i][5]))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         private_custname = u[1:]
            #
            #
            #         p = list(Instances.objects.values_list('label').filter(shape__contains=data[i][0],
            #                                                                     sshkeys__contains=data[i][5]))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         instlabel = u[1:]
            #
            #
            #         p = list(Ipreservation.objects.values_list('public_ip').filter(name__contains=instlabel))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         public_ip = u[1:]
            #
            #
            #         p = list(Instances.objects.values_list('name').filter(shape__contains=data[i][0],
            #                                                                sshkeys__contains=data[i][5]))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         instname = u[1:]
            #
            #
            #         p = list(Instances.objects.values_list('state').filter(shape__contains=data[i][0],
            #                                                               sshkeys__contains=data[i][5]))
            #         q = str(p).strip('[]')
            #         r = str(q).strip('()')  # Data purification
            #         s = r[:-1]
            #         t = s[1:]
            #         u = t[:-1]
            #         inst_state = u[1:]
            #
            #
            #     if shapeflag == 1 and datavolflag == 1 and appinstanceflag == 1 and tierflag == 1 and instanceflag == 1 and imageflag == 1 and sshflag == 1:
            #         status = 'VALID'                        # Validating status from all flags
            #         shapeflag = 0
            #         datavolflag = 0
            #         appinstanceflag = 0                     # Resetting the flags
            #         tierflag = 0
            #         instanceflag = 0
            #         imageflag = 0
            #         sshflag = 0
            #         if (Inventory.objects.filter(hostlabel__contains=hostlabel, authDomain__contains=authDomain)):
            #             messages.info(request, "Entry exists in Inventory")
            #             db_status = 'EXISTS'
            #             pass
            #         else:
            #             Inventory.objects.create(authDomain=authDomain, url=url, instname=instlabel,inst_state=inst_state, dccode=dccode,customer=customer, custcode=custcode,
            #                                      zone=zones, private_ip=private_ip,private_custname=private_custname, public_ip=public_ip,
            #                                      account=account, size=size, shape=data[i][0], image=data[i][6],
            #                                      datavolsize=data[i][1], appinstance=data[i][2],
            #                                      backupvolsize=backupvolsize, hostlabel=hostlabel, seclist=seclist,
            #                                      tier=data[i][3], instance=data[i][4], ssh=data[i][5],
            #                                      pagevolsize=pagevolsize, emvolsize=emvolsize, datacenter=datacenter, user=user)
            #             db_status = 'PUSHED'
            #             print "Inventory Loading Success..!!"
            #     else:
            #         status = 'INVALID'
            #         db_status = 'IGNORED'
            #     fstatus.append(status)              # Appending status to the list
            #     fdbstatus.append(db_status)         # Appending inventory status to the list

        # Zipping the data for template
        zipped_data = zip(fauthDomain,furl,fstorage,fdccode,fcustcode,faccount,fprivate,fpublic,fplatform,fsize,fshape,fimage,fdatavolsize,fappinstance,fbackupvolsize,fhostlabel,fseclist,ftier,finstance,fssh,fpagevolsize,femvolsize,fdatacenter)
        context = {
            'zipped_data': zipped_data,
            'data': data,
            'inventory': inventory,
            'instances': instances,
            'secrule': secrule,
            'seclists': seclists,
            'secapp': secapp,
            'secip': secip,
            'ipresereve_data': ipresereve_data,
            # 'sshkey': sshkey,
            'storagevolume': storagevolume,
            'orchestration': orchestration,
            'images': images,
            'fstatus': fstatus,
            'fdbstatus': fdbstatus,
            'length': length,
            'zones': zones,
            'authDomain': authDomain,
            'user': user,
            'fauthDomain': fauthDomain,
            'furl': furl,
            'fstorage': fstorage,
            'documents': documents,
            'fdccode': fdccode,
            'fcustcode': fcustcode,
            'fprivate': fprivate,
            'fpublic': fpublic,
            'fipnet': fipnet,
            'fplatform': fplatform,
            'fsize': fsize,
            'faccount': faccount,
            'form': form,
            'fshape': fshape,
            'fimage': fimage,
            'ftier': ftier,
            'finstance': finstance,
            'datavolsize': datavolsize,
            'appinstance': appinstance,
            'fdatavolsize': fdatavolsize,
            'fappinstance': fappinstance,
            'fbackupvolsize': fbackupvolsize,
            'fhostlabel': fhostlabel,
            'fseclist': fseclist,
            'fssh': fssh,
            'fpagevolsize': fpagevolsize,
            'femvolsize': femvolsize,
            'fdatacenter': fdatacenter,
            'orchname': orchname,
            'orchstatus': orchstatus,
            'imgname': imgname,
            'volname': volname,
            'volsize': volsize,
            'instname': instname,
            'ocpu': ocpu,
            'secrulename': secrulename,
            'secruleenable': secruleenable,
            'seclistname': seclistname,
            'seclistused': seclistused,
            'secapplnname': secapplnname,
            'secapppublic': secapppublic,
            'secipname': secipname,
            'secippublic': secippublic,
            'ipreservename': ipreservename,
            'ipreserveused': ipreserveused,
            'ipnetworkname': ipnetworkname,
            'ipexchngname': ipexchngname,
            'vnicsets': vnicsets,
            'ipsecrulename': ipsecrulename,
            'ipsecruleenable': ipsecruleenable,
            'aclname': aclname,
            'secprotocolname': secprotocolname,
            'ipaddrprefixsetname': ipaddrprefixsetname,
            'ipnetworkreservename': ipnetworkreservename,
            'sshname': sshname,
            'sshenabled': sshenabled,
            'ipnetworks': ipnetworks,
            'ipexchanges': ipexchanges,
            'VNICset': VNICset,
            'ipsecrule': ipsecrule,
            'acls': acls,
            'aclenable': aclenable,
            'secprotocol': secprotocol,
            'ipaddrprefixset': ipaddrprefixset,
            'ipnetworkreserve': ipnetworkreserve,
            'sshkey': sshkey,
            'missing_secrule': missing_secrule,
            'missing_source': missing_source,
            'missing_dst': missing_dst,
            'missing': missing,
        }
        return render(request, template_name, context)                   #return the page requestfor the template page
    else:
        print "GET Type"

        form = DocumentForm()  # A empty, unbound form

        # Load documents for the list page
        documents = Document.objects.all()
        user = None
        # connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
        # cursord = connection.cursor()
        # cursord.execute('''select idd from idd_data GROUP BY idd''')
        # Domain = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select customer from idd_data GROUP BY customer''')
        # customer = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select zone from idd_data GROUP BY zone''')
        # zone = dictfetchall(cursord)

        context = {
            # 'Domain': Domain,
            # 'customer': customer,
            # 'zone': zone,
            'user': user,
            'documents': documents,
            'form': form,
        }
        return render(request, template_name,context)

def report(request, template_name='report.html'):
    strsearch = request.POST.get('term', '')
    repo = request.POST.get('report', '')

    user = listfetchall(list(Auth.objects.values_list('username').distinct()))
    password = listfetchall(list(Auth.objects.values_list('password').distinct()))
    (authDomain, api_id_id, url, customer_id_id, customer, storage, dccode, custcode, account, zone) = cap_var(request)
    image = listfetchall(list(Orchestration.objects.values_list('imagelist').distinct()))

    storage_api = listfetchall(list(Idd_data.objects.values_list('storage').distinct().filter(idd__contains=authDomain)))
    storage_cookie = authenticate_oscs.authenticate(storage_api, 'Storage-' + authDomain + ':' + user, password)

    # Gather Object Storage Replication and Bytes Used
    headers = {'X-Auth-Token': storage_cookie[0]}
    session = requests.Session()
    r = session.get(storage_cookie[1], headers=headers)
    object_storage_usage = int(r.headers['X-Account-Bytes-Used'])
    georeplication = r.headers['X-Account-Meta-Policy-Georeplication']
    total_object_storage_used_gb = object_storage_usage / (1024.0 * 1024.0 * 1024.0)

    pattern = re.compile(r'\w{2}\d-\w{2}\d')
    if re.search(pattern, georeplication):
        total_object_storage_used_gb *= 2

    apipattern = re.match('https://.*compute.(.*).oraclecloud', url)
    location = apipattern.group(1)
    instance_count = Instances.objects.all().values('inst_name').count()
    cpu_used = list(Instances.objects.all().values('total_cpu_used').distinct())
    total_cpu_used = int(cpu_used[0]['total_cpu_used'])
    volsizes = StorageVolume.objects.aggregate(vol_size=Sum('size'))
    total_block_storage_used_gb = volsizes['vol_size'] / (1024.0 * 1024.0 * 1024.0)
    eip_count = Ipreservation.objects.all().values_list('name').count()

    # Simple Maths
    total_cpu_allocated = 54
    total_block_storage_allocated_gb = 14000
    total_object_storage_allocated_gb = 14000
    object_storage_available_gb = int(total_object_storage_allocated_gb) - int(total_object_storage_used_gb)
    block_storage_available_gb =  int(total_block_storage_allocated_gb) - int(total_block_storage_used_gb)
    cpu_available = int(total_cpu_allocated) - int(total_cpu_used)

    connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
    cursord = connection.cursor()
    cursord.execute('''CREATE OR REPLACE VIEW inst_report as SELECT p1.inst_domain,p1.state,p1.vnc,p1.storage_name,p1.fingerprint,p1.private_ip,p1.label,p1.platform,p1.inst_name,
    p1.shape,p1.location,p1.total_block_storage_used,p1.total_cpu_used,p2.inst_seclist,p2.imagelist, now() AS time_stamp FROM instances as p1 INNER JOIN orchestration as p2 on p1.inst_name=p2.inst_name;''')

    cursord.execute('''CREATE OR REPLACE VIEW storage_report as SELECT p1.name,p1.status,p1.account,p1.writecache,p1.managed,p1.description,p1.tags,p1.bootable,p1.hypervisor,p1.quota,p1.uri,p1.status_detail,
                    p1.imagelist_entry,p1.storage_pool,p1.machineimage_name,p1.status_timestamp,p1.shared,p1.size,p1.properties,p2.inst_name,p2.inst_shape,p2.inst_label,p2.inst_seclist,p2.private_ip,
                    p2.state,p2.imagelist,p2.ssh_name,p2.location,p2.total_block_storage_used,p2.total_cpu_used, now() AS time_stamp FROM storagevolume as p1 INNER JOIN orchestration as p2 on p1.name=p2.storage;''')

    cursord.execute('''CREATE OR REPLACE VIEW shared_report as SELECT p1.name,p1.application,p1.src_list,p1.dst_list,p1.disabled,p1.action,p2.protocol,p2.dport,p3.inst_name,p3.inst_shape,p3.inst_label,p3.inst_seclist,p3.private_ip,
                    p3.state,p3.imagelist,p3.ssh_name,p3.location,p3.total_block_storage_used,p3.total_cpu_used,p4.outbound_cidr_policy,p4.policy,p5.public_ip,p5.parentpool,now() AS time_stamp
                    FROM secrule as p1 INNER JOIN secappln as p2 on p1.application = p2.name, orchestration as p3 INNER JOIN seclist as p4 on p3.inst_seclist=p4.name INNER JOIN ipreserve as p5 on p3.ipreserve LIKE CONCAT('%',p5.name , '%');''')

    cursord.execute('''CREATE OR REPLACE VIEW ip_report as SELECT p1.name,p1.description,p1.acl,p1.flowdirection,p1.srcVnicSet,p1.dstVnicSet,p1.srcIpAddressPrefixSets,p1.dstIpAddressPrefixSets,
    p1.secProtocols,p1.enabledFlag,now() AS time_stamp FROM ipsecrule as p1 INNER JOIN acls as p2 on p1.acl=p2.name;''')
    #,p3.ipAddressPrefixes,p4.ipProtocol,p4.srcPortSet,p4.dstPortSet
    #INNER JOIN ipaddrprefixsets as p3 on p3.name=p1.srcIpAddressPrefixSets OR p3.name=p1.dstIpAddressPrefixSets INNER JOIN secprotocols as p4 on p4.name=p1.secProtocols;''')
    cursord.execute('''CREATE OR REPLACE VIEW image_report as SELECT p1.image_name,p1.location,p2.total_block_storage_used,p2.total_cpu_used,p2.inst_name,p2.inst_shape,p2.inst_seclist,p2.private_ip,p2.storage,p2.ssh_name,p2.ipreserve FROM image as p1 INNER JOIN orchestration as p2 on p1.image_name=p2.imagelist''')

    # rule_seclist = None
    # if 'ruleseclistbtn' in request.POST:
    #     rule_seclist = listfetchall(list(SecRule.objects.all().filter(src_list__contains='seclist', dst_list__contains='seclist')))
    #     print rule_seclist

    rseclist = listfetchall(list(SecRule.objects.values_list('name').filter(src_list__contains='seclist', dst_list__contains='seclist')))
    # if 'ruleseclist' in request.POST:
    #     rseclist = listfetchall(list(SecRule.objects.values_list('name').filter(src_list__contains='seclist', dst_list__contains='seclist')))
    #     print rseclist

    instances = None
    reports_instances = None
    shared = None
    reports_shared = None
    ip = None
    reports_ip = None
    storage = None
    reports_storage = None
    orchestration = None
    reports_orch = None
    image = None
    reports_image = None
    if 'strsearch' in request.POST:
        if repo == 'instance':
            instances = listfetchall(list(Instances.objects.values_list('inst_name').filter(inst_name__contains=strsearch)))
            #reports_instances = Instances.objects.all().filter(name__contains=strsearch)
            cursord = connection.cursor()
            cursord.execute('''select inst_name,inst_domain,state,vnc,storage_name,fingerprint,private_ip,label,platform,shape,location,total_block_storage_used,total_cpu_used,inst_seclist,imagelist from
            inst_report where inst_name="%s";''' % (strsearch))
            reports_instances = dictfetchall(cursord)
            messages.success(request, "You looking for : {0}".format(instances))
        if repo == 'network':
            shared = listfetchall(list(SecRule.objects.values_list('name').filter(name__contains=strsearch)))
            if shared != '':
                cursord = connection.cursor()
                cursord.execute('''select name,application,src_list,dst_list,disabled,action,protocol,dport,inst_name,inst_shape,inst_label,inst_seclist,private_ip,
                                    state,imagelist,ssh_name,location,total_block_storage_used,total_cpu_used,outbound_cidr_policy,policy,public_ip,parentpool,time_stamp from shared_report where
                                    name="%s"''' % (strsearch))
                reports_shared = dictfetchall(cursord)
                print "shared"
                print shared
                messages.success(request, "You looking for : {0}".format(shared))
            if shared == '':
                ip = listfetchall(list(IPSecRule.objects.values_list('name').filter(name__contains=strsearch)))
                cursord = connection.cursor()
                cursord.execute('''select name,description,acl,flowdirection,srcVnicSet,dstVnicSet,srcIpAddressPrefixSets,dstIpAddressPrefixSets,
                secProtocols,enabledFlag,time_stamp from ip_report where name="%s"''' % (strsearch))
                reports_ip = dictfetchall(cursord)
                print "ip"
                print reports_ip
                messages.success(request, "You looking for : {0}".format(ip))
        if repo == 'storage':
            storage = listfetchall(list(StorageVolume.objects.values_list('name').filter(name__contains=strsearch)))
            #reports_storage = StorageVolume.objects.all().filter(name__contains=strsearch)
            cursord = connection.cursor()
            cursord.execute('''select name,status,account,writecache,managed,description,tags,bootable,hypervisor,quota,uri,status_detail,imagelist_entry,storage_pool,machineimage_name,status_timestamp,shared,
                            size,properties,inst_name,inst_shape,inst_label,inst_seclist,private_ip,state,ssh_name,location,total_block_storage_used,total_cpu_used from storage_report
                            where name="%s";''' % (strsearch))
            reports_storage = dictfetchall(cursord)
            messages.success(request, "You looking for : {0}".format(storage))
        if repo == 'orchestrations':
            orchestration = listfetchall(list(Orchestration.objects.values_list('name').filter(name__contains=strsearch)))
            reports_orch = Orchestration.objects.all().filter(name__contains=strsearch)
            messages.success(request, "You looking for : {0}".format(orchestration))
        if repo == 'images':
            image = listfetchall(list(Image.objects.values_list('image_name').filter(image_name__contains=strsearch)))
            cursord = connection.cursor()
            cursord.execute('''select image_name,location,total_block_storage_used,total_cpu_used,inst_name,inst_shape,inst_seclist,private_ip,storage,ssh_name,ipreserve from image_report
                            where image_name="%s";''' % (strsearch))
            #reports_image = Image.objects.all().filter(image_name__contains=strsearch)
            reports_image = dictfetchall(cursord)
            messages.success(request, "You looking for : {0}".format(image))
        #instances = Instances.objects.values_list('name').filter(name__contains=strsearch)
        # instances = Report.objects.values_list('name').filter(name__contains=strsearch)
        # reports = Report.objects.all().filter(name__contains=strsearch)
        #messages.success(request,"You looking for : {0}".format(instances))
    context = {
        'instances': instances,
        'reports_instances': reports_instances,
        'shared': shared,
        'reports_shared': reports_shared,
        'ip': ip,
        'reports_ip': reports_ip,
        'storage': storage,
        'reports_storage': reports_storage,
        'orchestration': orchestration,
        'reports_orch': reports_orch,
        'image': image,
        'reports_image': reports_image,
        'authDomain': authDomain,
        'location': location,
        'instance_count': instance_count,
        'eip_count': eip_count,
        'total_cpu_allocated': total_cpu_allocated,
        'total_cpu_used': total_cpu_used,
        'cpu_available': cpu_available,
        'total_block_storage_allocated_gb': total_block_storage_allocated_gb,
        'total_block_storage_used_gb': total_block_storage_used_gb,
        'block_storage_available_gb': block_storage_available_gb,
        'total_object_storage_allocated_gb': total_object_storage_allocated_gb,
        'total_object_storage_used_gb': total_object_storage_used_gb,
        'object_storage_available_gb': object_storage_available_gb,
        # 'rule_seclist': rule_seclist,
        'rseclist': rseclist,
    }
    return render(request, template_name, context)

# @csrf_exempt
# def getSecIpListHosts(request, template_name='port.html'):
#     if request.method == 'GET':
#         secHostname = request.GET['seciplist']
#         seciplistCursor = connection.cursor()
#         seciplistCursor.execute('''select secipentries from ip_list where name=%s ''', secHostname)
#         secHostname_data = dictfetchall(seciplistCursor)
#         json_data = json.dumps(secHostname_data)
#         return HttpResponse(json_data, content_type = "application/json")

@csrf_exempt
def getPublicIp(request, template_name='port.html'):
    if request.method == 'GET':
        seclistName = request.GET['seclist']
        #seclistName = 'SL-OMCSSERVICEDOM1'
        connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
        seclistNameCursor = connection.cursor()
        #seclistNameCursor.execute('''select private_ip from orchestration where inst_seclist like '%s'; ''', seclistName)
        private_ip=listfetchall(list(Orchestration.objects.values_list('private_ip').distinct().filter(inst_seclist__contains=seclistName)))
        #private_ip = dictfetchall(seclistNameCursor)
        publicIpJson_data = json.dumps(private_ip)
        return HttpResponse(publicIpJson_data, content_type = "application/json")

def validviews(request, template_name='valid.html'):            # Function for valid data(2nd page)
    if request.method == 'POST':
        #(authDomain, api_id_id, url, customer_id_id, customer, storage, dccode, custcode, account, zone) = cap_var(request)
        print "2nd page disp"

        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']



        # shape  = request.POST.get('shape_name', '')
        # image = request.POST.get('image_name', '')
        # datavolsize = request.POST.get('datavol', '')
        # appinstance = request.POST.get('ainstance', '')
        # tier = request.POST.get('tier_name', '')
        # instance = request.POST.get('inst_name', '')
        # sshkeys = request.POST.get('ssh_name','')
        # size = '32'
        # pagevolsize = None
        # emvolsize = None
        # datacenter = None
        # if "Microsoft" in image:
        #     p = list(Shapes.objects.values_list('ram').filter(shape_name=shape))
        #     q = str(p).strip('[]')
        #     r = str(q).strip('()')
        #     s = r[:-1]
        #     t = s[1:]
        #     u = t[:-1]
        #     rams = u[1:]
        #     ramint = int(rams)
        #     ram = ramint / 1024
        #     pagevolsize = (ram * 1.5) + 1
        #     emvolsize = 10
        #     datacenter = url[24:27]
        #     size = '64'
        #
        #
        # connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")
        # cursord = connection.cursor()
        # cursord.execute('''select shape_name from shape where shape_name="%s"''' % (shape))
        # shape_name = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select size_name from size where size_name="%s"''' %(size))
        # size_name = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select image_name from image where image_name="%s"''' % (image))
        # image_name = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select tier_name from tier where tier_name="%s"''' % (tier))
        # tier_name = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select inst_name from instance where inst_name="%s"''' % (instance))
        # inst_name = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select ssh_name from sshkeys where ssh_name="%s"''' % (sshkeys))
        # ssh_name = dictfetchall(cursord)
        #
        # sizeno = int(size)
        # data = int(datavolsize)
        # footprint = sizeno + data
        # backupvolsize = footprint * 1.5
        # hostlabel = '%s-%s-01' %(appinstance,instance)
        # seclist = 'SL-%s-%s-%s-001' %(custcode,tier,instance)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select image_name from image GROUP BY image_name''')
        # image = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select shape_name from shape GROUP BY shape_name''')
        # shape = dictfetchall(cursord)
        #
        # cursord = connection.cursor()
        # cursord.execute('''select ssh_name from sshkeys GROUP BY ssh_name''')
        # sshkeys = dictfetchall(cursord)


        context = {
            # 'authDomain': authDomain,
            # 'url': url,
            # 'dccode': dccode,
            # 'image': image,
            # 'shape': shape,
            # 'custcode': custcode,
            # 'datavolsize': datavolsize,
            # 'appinstance': appinstance,
            # 'backupvolsize': backupvolsize,
            # 'hostlabel': hostlabel,
            # 'seclist': seclist,
            # 'sshkeys': sshkeys,
            # 'image_name': image_name,
            # 'shape_name': shape_name,
            # 'size_name': size_name,
            # 'tier_name': tier_name,
            # 'inst_name': inst_name,
            # 'ssh_name': ssh_name,
            # 'account': account,
            # 'pagevolsize': pagevolsize,
            # 'emvolsize': emvolsize,
            # 'datacenter': datacenter,
            'name': name,
            'email': email,
            'password': password,
        }
        return render(request, template_name,context)
    else:
        print "valid GET type"
        connection = MySQLdb.connect("localhost", "root", "Dev0p$123", "prov")

        cursord = connection.cursor()
        cursord.execute('''select image_name from image GROUP BY image_name''')
        image = dictfetchall(cursord)

        cursord = connection.cursor()
        cursord.execute('''select shape_name from shape GROUP BY shape_name''')
        shape = dictfetchall(cursord)

        cursord = connection.cursor()
        cursord.execute('''select ssh_name from sshkeys GROUP BY ssh_name''')
        sshkeys = dictfetchall(cursord)

        context = {
            'image': image,
            'shape' : shape,
            'sshkeys': sshkeys,
        }
        return render(request, template_name,context)

def help(request, template_name='help.html'):

    return render(request, template_name)
