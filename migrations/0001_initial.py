# -*- coding: utf-8 -*-
# Generated by Django 1.10.4 on 2017-12-08 12:39
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ACLs',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('enabledFlag', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'acls',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Api',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('api', models.CharField(max_length=255, null=True)),
            ],
            options={
                'db_table': 'api',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Auth',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(blank=True, max_length=255, null=True)),
                ('password', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'auth',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Customer',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('customer', models.CharField(max_length=255, null=True)),
            ],
            options={
                'db_table': 'customer',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('docfile', models.FileField(upload_to='documents')),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dom', models.CharField(blank=True, max_length=255, null=True)),
                ('zone', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'dom',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Idd_data',
            fields=[
                ('idd', models.CharField(max_length=255)),
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('storage', models.CharField(max_length=255)),
                ('dccode', models.CharField(max_length=255)),
                ('custcode', models.CharField(max_length=255)),
                ('zone', models.CharField(max_length=255)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'idd_data',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Image',
            fields=[
                ('deflt', models.IntegerField()),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('images', models.CharField(blank=True, max_length=255, null=True)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('image_name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('machineimages', models.CharField(max_length=255)),
                ('location', models.CharField(blank=True, max_length=255)),
                ('total_block_storage_used', models.CharField(blank=True, max_length=255)),
                ('total_cpu_used', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'image',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Instance',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('inst_name', models.CharField(max_length=255, null=True)),
            ],
            options={
                'db_table': 'instance',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Instances',
            fields=[
                ('domain', models.CharField(max_length=255, null=True)),
                ('placement_requirements', models.CharField(max_length=255, null=True)),
                ('site', models.CharField(max_length=255, null=True)),
                ('imagelist', models.CharField(max_length=255, null=True)),
                ('attributes', models.CharField(max_length=255, null=True)),
                ('sshkeys', models.CharField(max_length=255, null=True)),
                ('networking', models.CharField(max_length=255, null=True)),
                ('hostname', models.CharField(max_length=255, null=True)),
                ('dns_hostname', models.CharField(max_length=255, null=True)),
                ('quota_reservation', models.CharField(max_length=255, null=True)),
                ('disk_attach', models.CharField(max_length=255, null=True)),
                ('priority', models.CharField(max_length=255, null=True)),
                ('state', models.CharField(max_length=255, null=True)),
                ('vnc', models.CharField(max_length=255, null=True)),
                ('storage_name', models.CharField(max_length=2047, null=True)),
                ('quota', models.CharField(max_length=255, null=True)),
                ('fingerprint', models.CharField(max_length=255, null=True)),
                ('error_reason', models.CharField(max_length=255, null=True)),
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('vcable_id', models.CharField(max_length=255, null=True)),
                ('uri', models.CharField(max_length=255, null=True)),
                ('reverse_dns', models.CharField(max_length=255, null=True)),
                ('entry', models.CharField(max_length=255, null=True)),
                ('boot_order', models.CharField(max_length=255, null=True)),
                ('private_ip', models.CharField(max_length=255, null=True)),
                ('inst_state', models.CharField(max_length=255, null=True)),
                ('label', models.CharField(max_length=255, null=True)),
                ('platform', models.CharField(max_length=255, null=True)),
                ('shape', models.CharField(max_length=255, null=True)),
                ('attributes_id', models.CharField(max_length=255, null=True)),
                ('location', models.CharField(blank=True, max_length=255)),
                ('total_block_storage_used', models.CharField(blank=True, max_length=255)),
                ('total_cpu_used', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'instances',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Inventory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('authDomain', models.CharField(max_length=255, null=True)),
                ('url', models.CharField(max_length=255, null=True)),
                ('instname', models.CharField(max_length=255, null=True)),
                ('inst_state', models.CharField(max_length=255, null=True)),
                ('dccode', models.CharField(max_length=255, null=True)),
                ('customer', models.CharField(max_length=255, null=True)),
                ('custcode', models.CharField(max_length=255, null=True)),
                ('zone', models.CharField(max_length=255, null=True)),
                ('private_ip', models.CharField(max_length=255, null=True)),
                ('private_hostname', models.CharField(max_length=255, null=True)),
                ('public_ip', models.CharField(max_length=255, null=True)),
                ('account', models.CharField(max_length=255)),
                ('size', models.CharField(max_length=255, null=True)),
                ('shape', models.CharField(max_length=255, null=True)),
                ('image', models.CharField(max_length=255, null=True)),
                ('datavolsize', models.CharField(max_length=255, null=True)),
                ('appinstance', models.CharField(max_length=255, null=True)),
                ('backupvolsize', models.CharField(max_length=255, null=True)),
                ('hostlabel', models.CharField(max_length=255, null=True)),
                ('seclist', models.CharField(max_length=255, null=True)),
                ('tier', models.CharField(max_length=255, null=True)),
                ('instance', models.CharField(max_length=255, null=True)),
                ('ssh', models.CharField(max_length=255, null=True)),
                ('pagevolsize', models.CharField(max_length=255, null=True)),
                ('emvolsize', models.CharField(max_length=255, null=True)),
                ('datacenter', models.CharField(max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'inventory',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='IpAddrPrefixSets',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=2047, null=True)),
                ('description', models.CharField(blank=True, max_length=2047, null=True)),
                ('tags', models.CharField(blank=True, max_length=2047, null=True)),
                ('ipAddressPrefixes', models.CharField(blank=True, max_length=2047, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipaddrprefixsets',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='IpAssociation',
            fields=[
                ('account', models.CharField(blank=True, max_length=255)),
                ('vcable', models.CharField(blank=True, max_length=255)),
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('ip', models.CharField(blank=True, max_length=255)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('parentpool', models.CharField(blank=True, max_length=255)),
                ('reservation', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipassociation',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Ipnetwork',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('ipAddressPrefix', models.CharField(blank=True, max_length=255, null=True)),
                ('ipNetworkExchange', models.CharField(blank=True, max_length=255, null=True)),
                ('publicNaptEnabledFlag', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipnetwork',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='IpNetworkExchange',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipnetworkexchange',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Ipnetworkreservation',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('ipAddress', models.CharField(blank=True, max_length=255, null=True)),
                ('ipAddressPool', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipnetworkreserve',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Ipreservation',
            fields=[
                ('account', models.CharField(blank=True, max_length=255, null=True)),
                ('used', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('quota', models.CharField(blank=True, max_length=255, null=True)),
                ('parentpool', models.CharField(blank=True, max_length=255, null=True)),
                ('permanent', models.CharField(blank=True, max_length=255, null=True)),
                ('public_ip', models.CharField(blank=True, max_length=255, null=True)),
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipreserve',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='IPSecRule',
            fields=[
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('acl', models.CharField(blank=True, max_length=255, null=True)),
                ('flowdirection', models.CharField(blank=True, max_length=255, null=True)),
                ('srcVnicSet', models.CharField(blank=True, max_length=255, null=True)),
                ('dstVnicSet', models.CharField(blank=True, max_length=255, null=True)),
                ('srcIpAddressPrefixSets', models.CharField(blank=True, max_length=255, null=True)),
                ('dstIpAddressPrefixSets', models.CharField(blank=True, max_length=255, null=True)),
                ('secProtocols', models.CharField(blank=True, max_length=255, null=True)),
                ('enabledFlag', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'ipsecrule',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Orchestration',
            fields=[
                ('status', models.CharField(blank=True, max_length=255, null=True)),
                ('sccount', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('schedule', models.CharField(blank=True, max_length=255, null=True)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('oplans', models.CharField(blank=True, max_length=255, null=True)),
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('location', models.CharField(blank=True, max_length=255)),
                ('total_block_storage_used', models.CharField(blank=True, max_length=255)),
                ('total_cpu_used', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'orchestration',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('domain', models.CharField(blank=True, max_length=255)),
                ('hostname', models.CharField(blank=True, max_length=255)),
                ('priority', models.CharField(blank=True, max_length=255)),
                ('state', models.CharField(blank=True, max_length=255)),
                ('vnc', models.CharField(blank=True, max_length=255)),
                ('storage_name', models.CharField(max_length=2047, null=True)),
                ('quota', models.CharField(blank=True, max_length=255)),
                ('fingerprint', models.CharField(blank=True, max_length=255)),
                ('reverse_dns', models.CharField(blank=True, max_length=255)),
                ('boot_order', models.CharField(blank=True, max_length=255)),
                ('private_ip', models.CharField(blank=True, max_length=255)),
                ('inst_state', models.CharField(blank=True, max_length=255)),
                ('label', models.CharField(blank=True, max_length=255)),
                ('platform', models.CharField(blank=True, max_length=255)),
                ('shape', models.CharField(blank=True, max_length=255)),
                ('attributes_id', models.CharField(blank=True, max_length=255)),
                ('location', models.CharField(blank=True, max_length=255)),
                ('total_block_storage_used', models.CharField(blank=True, max_length=255)),
                ('total_cpu_used', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'report',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='SecApp',
            fields=[
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('protocol', models.CharField(blank=True, max_length=50, null=True)),
                ('uri', models.CharField(blank=True, max_length=50, null=True)),
                ('dport', models.CharField(blank=True, max_length=50, null=True)),
                ('public', models.CharField(max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'secappln',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Secip',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('secipentries', models.CharField(max_length=2047)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'secip',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Seclist',
            fields=[
                ('account', models.CharField(blank=True, max_length=255, null=True)),
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('outbound_cidr_policy', models.CharField(blank=True, max_length=255, null=True)),
                ('policy', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'seclist',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='SecProtocols',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('ipProtocol', models.CharField(blank=True, max_length=255, null=True)),
                ('srcPortSet', models.CharField(blank=True, max_length=255, null=True)),
                ('dstPortSet', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'secprotocols',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='SecRule',
            fields=[
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('application', models.CharField(blank=True, max_length=255, null=True)),
                ('src_list', models.CharField(blank=True, max_length=255, null=True)),
                ('dst_list', models.CharField(blank=True, max_length=255, null=True)),
                ('uri', models.CharField(max_length=255, null=True)),
                ('disabled', models.CharField(blank=True, max_length=255, null=True)),
                ('action', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'secrule',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Shapes',
            fields=[
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('cpus', models.CharField(blank=True, max_length=255, null=True)),
                ('io', models.CharField(blank=True, max_length=255, null=True)),
                ('nds_iops_limit', models.CharField(blank=True, max_length=255, null=True)),
                ('shape_name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('ram', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'shape',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='SSHkeys',
            fields=[
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('key', models.CharField(blank=True, max_length=2047, null=True)),
                ('enabled', models.CharField(blank=True, max_length=255)),
                ('ssh_name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'sshkeys',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='StorageVolume',
            fields=[
                ('status', models.CharField(blank=True, max_length=255, null=True)),
                ('account', models.CharField(blank=True, max_length=255, null=True)),
                ('writecache', models.CharField(blank=True, max_length=255, null=True)),
                ('managed', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('bootable', models.BooleanField(default=True)),
                ('hypervisor', models.CharField(blank=True, max_length=255, null=True)),
                ('quota', models.CharField(blank=True, max_length=255, null=True)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('status_detail', models.CharField(blank=True, max_length=255, null=True)),
                ('imagelist_entry', models.CharField(blank=True, max_length=255, null=True)),
                ('storage_pool', models.CharField(blank=True, max_length=255, null=True)),
                ('machineimage_name', models.CharField(blank=True, max_length=255, null=True)),
                ('status_timestamp', models.DateTimeField()),
                ('shared', models.BooleanField()),
                ('imagelist', models.CharField(blank=True, max_length=255, null=True)),
                ('size', models.BigIntegerField()),
                ('properties', models.CharField(blank=True, max_length=255, null=True)),
                ('name', models.CharField(blank=True, max_length=255, primary_key=True, serialize=False)),
                ('location', models.CharField(blank=True, max_length=255)),
                ('total_block_storage_used', models.CharField(blank=True, max_length=255)),
                ('total_cpu_used', models.CharField(blank=True, max_length=255)),
                ('user', models.CharField(blank=True, max_length=255)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'storagevolume',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Tier',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tier_name', models.CharField(max_length=255, null=True)),
            ],
            options={
                'db_table': 'tier',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='VNICsets',
            fields=[
                ('name', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uri', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.CharField(blank=True, max_length=255, null=True)),
                ('tags', models.CharField(blank=True, max_length=255, null=True)),
                ('vnics', models.CharField(blank=True, max_length=255, null=True)),
                ('appliedAcls', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.CharField(blank=True, max_length=255, null=True)),
                ('api_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api')),
                ('customer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer')),
            ],
            options={
                'db_table': 'vnicsets',
                'managed': True,
            },
        ),
        migrations.AddField(
            model_name='acls',
            name='api_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Api'),
        ),
        migrations.AddField(
            model_name='acls',
            name='customer_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Customer'),
        ),
        migrations.AlterUniqueTogether(
            name='vnicsets',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='storagevolume',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='sshkeys',
            unique_together=set([('ssh_name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='shapes',
            unique_together=set([('shape_name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='secrule',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='secprotocols',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='seclist',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='secip',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='secapp',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='report',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='orchestration',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipsecrule',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipreservation',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipnetworkreservation',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipnetworkexchange',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipnetwork',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipassociation',
            unique_together=set([('vcable', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='ipaddrprefixsets',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='instances',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='image',
            unique_together=set([('image_name', 'api_id', 'customer_id')]),
        ),
        migrations.AlterUniqueTogether(
            name='acls',
            unique_together=set([('name', 'api_id', 'customer_id')]),
        ),
    ]
