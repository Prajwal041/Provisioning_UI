from __future__ import unicode_literals

from django.db import models

import os

from django.conf import settings
# Create your models here.
class Domain(models.Model):
    dom = models.CharField(max_length=255, blank=True, null=True)
    zone = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'dom'

class Auth(models.Model):
    username = models.CharField(max_length=255, blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'auth'

class Api(models.Model):
    id = models.IntegerField(primary_key=True)
    api = models.CharField(max_length=255, blank=False, null=True)

    class Meta:
        managed = True
        db_table = 'api'

class Customer(models.Model):
    id = models.IntegerField(primary_key=True)
    customer = models.CharField(max_length=255, blank=False, null=True)

    class Meta:
        managed = True
        db_table = 'customer'

class Idd_data(models.Model):
    idd = models.CharField(max_length=255, blank=False, null=False)
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    storage = models.CharField(max_length=255, blank=False, null=False)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    dccode = models.CharField(max_length=255, blank=False, null=False)
    custcode = models.CharField(max_length=255, blank=False, null=False)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)
    zone = models.CharField(max_length=255, blank=False, null=False)

    class Meta:
        managed = True
        db_table = 'idd_data'

class Tier(models.Model):
    tier_name = models.CharField(max_length=255, blank=False, null=True)

    class Meta:
        managed = True
        db_table = 'tier'

class Instance(models.Model):
    inst_name = models.CharField(max_length=255, blank=False, null=True)

    class Meta:
        managed = True
        db_table = 'instance'

class Shapes(models.Model):
    uri = models.CharField(max_length=255, blank=True, null=True)
    cpus = models.CharField(max_length=255, blank=True, null=True)
    io = models.CharField(max_length=255, blank=True, null=True)
    nds_iops_limit = models.CharField(max_length=255, blank=True, null=True)
    shape_name = models.CharField(max_length=255, blank=False, null=False, primary_key= True)
    ram = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'shape'
        unique_together = (('shape_name','api_id','customer_id'),)

class Image(models.Model):
    deflt = models.IntegerField()
    description = models.CharField(max_length=255, blank=True, null=True)
    images = models.CharField(max_length=255, blank=True, null=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    image_name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    machineimages = models.CharField(max_length=255, blank=False, null=False)
    location = models.CharField(max_length=255, blank=True, null=False)
    total_block_storage_used = models.CharField(max_length=255, blank=True, null=False)
    total_cpu_used = models.CharField(max_length=255, blank=True, null=False)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'image'
        unique_together = (('image_name', 'api_id','customer_id'),)

class SSHkeys(models.Model):
    uri = models.CharField(max_length=255, blank=True, null=True)
    key = models.CharField(max_length=2047, blank=True, null=True)
    enabled = models.CharField(max_length=255, blank=True, null=False)
    ssh_name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'sshkeys'
        unique_together = (('ssh_name', 'api_id','customer_id'),)

class Inventory(models.Model):
    authDomain = models.CharField(max_length=255, blank=False, null=True)
    url = models.CharField(max_length=255, blank=False, null=True)
    instname = models.CharField(max_length=255, blank=False, null=True)
    inst_state = models.CharField(max_length=255, blank=False, null=True)
    dccode = models.CharField(max_length=255, blank=False, null=True)
    customer = models.CharField(max_length=255, blank=False, null=True)
    custcode = models.CharField(max_length=255, blank=False, null=True)
    zone = models.CharField(max_length=255, blank=False, null=True)
    private_ip = models.CharField(max_length=255, blank=False, null=True)
    private_hostname = models.CharField(max_length=255, blank=False, null=True)
    public_ip = models.CharField(max_length=255, blank=False, null=True)
    #imagelist = models.CharField(max_length=255, blank=False, null=True)
    account = models.CharField(max_length=255, blank=False, null=False)
    size = models.CharField(max_length=255, blank=False, null=True)
    shape = models.CharField(max_length=255, blank=False, null=True)
    image = models.CharField(max_length=255, blank=False, null=True)
    datavolsize = models.CharField(max_length=255, blank=False, null=True)
    appinstance = models.CharField(max_length=255, blank=False, null=True)
    backupvolsize = models.CharField(max_length=255, blank=False, null=True)
    hostlabel = models.CharField(max_length=255, blank=False, null=True)
    seclist = models.CharField(max_length=255, blank=False, null=True)
    tier = models.CharField(max_length=255, blank=False, null=True)
    instance = models.CharField(max_length=255, blank=False, null=True)
    ssh = models.CharField(max_length=255, blank=False, null=True)
    pagevolsize = models.CharField(max_length=255, blank=False, null=True)
    emvolsize = models.CharField(max_length=255, blank=False, null=True)
    datacenter = models.CharField(max_length=255, blank=False, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = True
        db_table = 'inventory'

class Instances(models.Model):
    inst_domain = models.CharField(max_length=255, blank=False, null=True)
    placement_requirements = models.CharField(max_length=255, blank=False, null=True)
    site = models.CharField(max_length=255, blank=False, null=True)
    imagelist = models.CharField(max_length=255, blank=False, null=True)
    attributes = models.CharField(max_length=255, blank=False, null=True)
    sshkeys = models.CharField(max_length=2047, blank=False, null=True)
    networking_seclist = models.CharField(max_length=255, blank=False, null=True)
    hostname = models.CharField(max_length=255, blank=False, null=True)
    dns_hostname = models.CharField(max_length=255, blank=False, null=True)
    quota_reservation = models.CharField(max_length=255, blank=False, null=True)
    disk_attach = models.CharField(max_length=255, blank=False, null=True)
    priority = models.CharField(max_length=255, blank=False, null=True)
    state = models.CharField(max_length=255, blank=False, null=True)
    vnc = models.CharField(max_length=255, blank=False, null=True)
    storage_name = models.CharField(max_length=2047, blank=False, null=True)
    quota = models.CharField(max_length=255, blank=False, null=True)
    fingerprint = models.CharField(max_length=255, blank=False, null=True)
    error_reason = models.CharField(max_length=255, blank=False, null=True)
    inst_name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    vcable_id = models.CharField(max_length=255, blank=False, null=True)
    uri = models.CharField(max_length=255, blank=False, null=True)
    reverse_dns = models.CharField(max_length=255, blank=False, null=True)
    entry = models.CharField(max_length=255, blank=False, null=True)
    boot_order = models.CharField(max_length=255, blank=False, null=True)
    private_ip = models.CharField(max_length=255, blank=False, null=True)
    inst_state = models.CharField(max_length=255, blank=False, null=True)
    label = models.CharField(max_length=255, blank=False, null=True)
    platform = models.CharField(max_length=255, blank=False, null=True)
    shape = models.CharField(max_length=255, blank=False, null=True)
    attributes_id = models.CharField(max_length=255, blank=False, null=True)
    location = models.CharField(max_length=255, blank=True, null=False)
    total_block_storage_used = models.CharField(max_length=255, blank=True, null=False)
    total_cpu_used = models.CharField(max_length=255, blank=True, null=False)
    #shape = models.ForeignKey(Shapes, on_delete=models.CASCADE)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'instances'
        unique_together = (('inst_name', 'api_id','customer_id'),)

class Ipnetwork(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    ipAddressPrefix = models.CharField(max_length=255, blank=True, null=True)
    ipNetworkExchange = models.CharField(max_length=255, blank=True, null=True)
    publicNaptEnabledFlag = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipnetwork'
        unique_together = (('name', 'api_id','customer_id'),)


class IpNetworkExchange(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipnetworkexchange'
        unique_together = (('name', 'api_id', 'customer_id'),)

class VNICsets(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    vnics = models.CharField(max_length=255, blank=True, null=True)
    appliedAcls = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'vnicsets'
        unique_together = (('name', 'api_id', 'customer_id'),)

class IPSecRule(models.Model):
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    acl = models.CharField(max_length=255, blank=True, null=True)
    flowdirection = models.CharField(max_length=255, blank=True, null=True)
    srcVnicSet = models.CharField(max_length=255, blank=True, null=True)
    dstVnicSet = models.CharField(max_length=255, blank=True, null=True)
    srcIpAddressPrefixSets = models.CharField(max_length=255, blank=True, null=True)
    dstIpAddressPrefixSets = models.CharField(max_length=255, blank=True, null=True)
    secProtocols = models.CharField(max_length=255, blank=True, null=True)
    enabledFlag = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipsecrule'
        unique_together = (('name', 'api_id','customer_id'),)

class ACLs(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    enabledFlag = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'acls'
        unique_together = (('name', 'api_id', 'customer_id'),)

class SecProtocols(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    ipProtocol = models.CharField(max_length=255, blank=True, null=True)
    srcPortSet = models.CharField(max_length=255, blank=True, null=True)
    dstPortSet = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'secprotocols'
        unique_together = (('name', 'api_id', 'customer_id'),)

class IpAddrPrefixSets(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=2047, blank=True, null=True)
    description = models.CharField(max_length=2047, blank=True, null=True)
    tags = models.CharField(max_length=2047, blank=True, null=True)
    ipAddressPrefixes = models.CharField(max_length=2047, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipaddrprefixsets'
        unique_together = (('name', 'api_id', 'customer_id'),)

class Ipnetworkreservation(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    ipAddress = models.CharField(max_length=255, blank=True, null=True)
    ipAddressPool = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipnetworkreserve'
        unique_together = (('name', 'api_id','customer_id'),)

class Ipreservation(models.Model):
    account = models.CharField(max_length=255, blank=True, null=True)
    used = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    quota = models.CharField(max_length=255, blank=True, null=True)
    parentpool = models.CharField(max_length=255, blank=True, null=True)
    permanent = models.CharField(max_length=255, blank=True, null=True)
    public_ip = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipreserve'
        unique_together = (('name', 'api_id','customer_id'),)

class IpAssociation(models.Model):
    account = models.CharField(max_length=255, blank=True, null=False)
    vcable = models.CharField(max_length=255, blank=True, null=False)
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    ip = models.CharField(max_length=255, blank=True, null=False)
    uri = models.CharField(max_length=255, blank=True, null=True)
    parentpool = models.CharField(max_length=255, blank=True, null=False)
    reservation = models.CharField(max_length=255, blank=True, null=False)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'ipassociation'
        unique_together = (('vcable', 'api_id','customer_id'),)



class SecApp(models.Model):
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    protocol = models.CharField(max_length=50, blank=True, null=True)
    uri = models.CharField(max_length=50, blank=True, null=True)
    dport = models.CharField(max_length=50, blank=True, null=True)
    public = models.CharField(max_length=255, blank=False, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'secappln'
        unique_together = (('name', 'api_id','customer_id'),)


class SecRule(models.Model):
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    application = models.CharField(max_length=255, blank=True, null=True)
    src_list = models.CharField(max_length=255, blank=True, null=True)
    dst_list = models.CharField(max_length=255, blank=True, null=True)
    uri = models.CharField(max_length=255, blank=False, null=True)
    disabled = models.CharField(max_length=255, blank=True, null=True)
    action = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'secrule'
        unique_together = (('name', 'api_id','customer_id'),)

class Seclist(models.Model):
    account = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    outbound_cidr_policy = models.CharField(max_length=255, blank=True, null=True)
    policy = models.CharField(max_length=255, blank=True, null=True)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'seclist'
        unique_together = (('name', 'api_id','customer_id'),)


class Secip(models.Model):
    name = models.CharField(max_length=255, blank=False, null=False, primary_key=True)
    secipentries = models.CharField(max_length=2047, blank=False, null=False)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'secip'
        unique_together = (('name', 'api_id','customer_id'),)

class StorageVolume(models.Model):
    status = models.CharField(max_length=255, blank=True, null=True)
    account = models.CharField(max_length=255, blank=True, null=True)
    writecache = models.CharField(max_length=255, blank=True, null=True)
    managed = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    tags = models.CharField(max_length=255, blank=True, null=True)
    bootable = models.BooleanField(default=True)
    hypervisor = models.CharField(max_length=255, blank=True, null=True)
    quota = models.CharField(max_length=255, blank=True, null=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    status_detail = models.CharField(max_length=255, blank=True, null=True)
    imagelist_entry = models.CharField(max_length=255, blank=True, null=True)
    storage_pool = models.CharField(max_length=255, blank=True, null=True)
    machineimage_name = models.CharField(max_length=255, blank=True, null=True)
    status_timestamp = models.DateTimeField()
    shared = models.BooleanField()
    imagelist = models.CharField(max_length=255, blank=True, null=True)
    size = models.BigIntegerField()
    properties = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    location = models.CharField(max_length=255, blank=True, null=False)
    total_block_storage_used = models.CharField(max_length=255, blank=True, null=False)
    total_cpu_used = models.CharField(max_length=255, blank=True, null=False)
    user = models.CharField(max_length=255, blank=True, null=False)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'storagevolume'
        unique_together = (('name', 'api_id','customer_id'),)

class Orchestration(models.Model):
    status = models.CharField(max_length=255, blank=True, null=True)
    account = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    schedule = models.CharField(max_length=255, blank=True, null=True)
    uri = models.CharField(max_length=255, blank=True, null=True)
    inst_shape = models.CharField(max_length=255, blank=True, null=True)
    inst_seclist = models.CharField(max_length=255, blank=True, null=True)
    ipreserve = models.CharField(max_length=255, blank=True, null=True)
    inst_name = models.CharField(max_length=255, blank=True, null=True)
    inst_label = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255, blank=True, null=False, primary_key=True)
    private_ip = models.CharField(max_length=255, blank=True, null=False)
    state = models.CharField(max_length=255, blank=True, null=False)
    storage = models.CharField(max_length=2047, blank=True, null=False)
    imagelist = models.CharField(max_length=255, blank=True, null=False)
    ssh_name = models.CharField(max_length=255, blank=True, null=False)
    location = models.CharField(max_length=255, blank=True, null=False)
    total_block_storage_used = models.CharField(max_length=255, blank=True, null=False)
    total_cpu_used = models.CharField(max_length=255, blank=True, null=False)
    user = models.CharField(max_length=255, blank=True, null=True)
    api_id = models.ForeignKey(Api, on_delete=models.CASCADE)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'orchestration'
        unique_together = (('name', 'api_id', 'customer_id'),)


class Document(models.Model):
    docfile = models.FileField(upload_to='documents')
    user = models.CharField(max_length=255, blank=True, null=True)

    def __unicode__(self):
        return '%s' % (self.docfile.name)

    def delete(self, *args, **kwargs):
        os.remove(os.path.join(settings.MEDIA_ROOT, self.docfile.name))
        super(Document, self).delete(*args, **kwargs)



