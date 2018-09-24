# -*- coding: utf-8 -*-
from django import forms

class DocumentForm(forms.Form):
    docfile = forms.FileField(
        label='Select a file',
        help_text='max. 100 lines'
    )

# {
#     "status": "active",
#     "account": "/Compute-omcsservicedom1/default",
#     "time_updated": null,
#     "description": "US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001 assembly",
#     "tags": [],
#     "uri": "https://api-uscom-central-1.compute.usdc2.oraclecloud.com/platform/v1/orchestration/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch",
#     "time_created": "2017-11-21T23:55:32Z",
#     "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch",
#     "time_audited": "2017-12-12T11:11:45Z",
#     "objects": [
#         {
#             "relationships": [],
#             "account": "/Compute-omcsservicedom1/default",
#             "time_updated": null,
#             "desired_state": "inherit",
#             "description": "Instance US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001",
#             "persistent": false,
#             "uri": "https://api-uscom-central-1.compute.usdc2.oraclecloud.com/platform/v1/object/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch/e5a17f32-fbf1-4e4c-9ead-f504df6a16f5",
#             "template": {
#                 "networking": {
#                     "eth0": {
#                         "seclists": [
#                             "/Compute-omcsservicedom1/orchestration/SL-OMCS-ANSIBLE"
#                         ],
#                         "nat": "ipreservation:/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-eip",
#                         "dns": [
#                             "omcsbabhcbhosv"
#                         ]
#                     }
#                 },
#                 "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001",
#                 "boot_order": [
#                     1
#                 ],
#                 "storage_attachments": [
#                     {
#                         "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-boot",
#                         "index": 1
#                     },
#                     {
#                         "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-data01",
#                         "index": 2
#                     },
#                     {
#                         "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-backup01",
#                         "index": 3
#                     }
#                 ],
#                 "label": "US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001",
#                 "reverse_dns": true,
#                 "shape": "oc3",
#                 "attributes": {
#                     "userdata": {}
#                 },
#                 "sshkeys": [
#                     "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-key"
#                 ]
#             },
#             "label": "US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001",
#             "time_audited": "2017-12-12T11:11:35Z",
#             "version": 1,
#             "health": {
#                 "status": "active",
#                 "object": {
#                     "domain": "compute-omcsservicedom1.oraclecloud.internal.",
#                     "placement_requirements": [
#                         "/system/compute/placement/default",
#                         "/system/compute/pool/general",
#                         "/system/compute/allow_instances"
#                     ],
#                     "ip": "10.29.232.178",
#                     "fingerprint": "6f:93:f8:1f:51:d2:65:f4:fb:f2:24:fd:7b:ec:05:8f",
#                     "image_metadata_bag": "/oracle/machineimage_metadata/59d9b3040d3f41d091852c15ccfbd858",
#                     "site": "",
#                     "shape": "oc3",
#                     "imagelist": null,
#                     "image_format": "raw",
#                     "relationships": [],
#                     "availability_domain": "/ad1",
#                     "networking": {
#                         "eth0": {
#                             "model": "",
#                             "seclists": [
#                                 "/Compute-omcsservicedom1/orchestration/SL-OMCS-ANSIBLE"
#                             ],
#                             "dns": [
#                                 "omcsbabhcbhosv.compute-omcsservicedom1.oraclecloud.internal."
#                             ],
#                             "vethernet": "/oracle/public/default",
#                             "nat": "ipreservation:/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-eip"
#                         }
#                     },
#                     "storage_attachments": [
#                         {
#                             "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-boot",
#                             "index": 1,
#                             "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001/1117b446-1db0-4317-a7da-77060c2ff497/6f9aa348-2960-48fe-866e-b3d2413a60c6"
#                         },
#                         {
#                             "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-data01",
#                             "index": 2,
#                             "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001/1117b446-1db0-4317-a7da-77060c2ff497/97507eac-9ae0-4745-9735-fb4478cf9f94"
#                         },
#                         {
#                             "volume": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-backup01",
#                             "index": 3,
#                             "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001/1117b446-1db0-4317-a7da-77060c2ff497/4b4a3960-3b94-4a3a-998f-149c31d291ed"
#                         }
#                     ],
#                     "hostname": "omcsbabhcbhosv.compute-omcsservicedom1.oraclecloud.internal.",
#                     "quota_reservation": null,
#                     "disk_attach": "",
#                     "label": "US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001",
#                     "priority": "/oracle/public/default",
#                     "platform": "linux",
#                     "state": "running",
#                     "virtio": null,
#                     "vnc": "10.29.232.177:5900",
#                     "desired_state": "running",
#                     "tags": [],
#                     "start_time": "2017-11-21T23:55:40Z",
#                     "quota": "/Compute-omcsservicedom1",
#                     "entry": null,
#                     "error_reason": "",
#                     "sshkeys": [
#                         "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-key"
#                     ],
#                     "resolvers": null,
#                     "account": "/Compute-omcsservicedom1/default",
#                     "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001/1117b446-1db0-4317-a7da-77060c2ff497",
#                     "vcable_id": "/Compute-omcsservicedom1/mageshwaran.k.kasi@oracle.com/dcf683e7-9452-4b59-8293-445bd2e81568",
#                     "hypervisor": {
#                         "mode": "hvm"
#                     },
#                     "uri": "https://api-uscom-central-1.compute.usdc2.oraclecloud.com/instance/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001/1117b446-1db0-4317-a7da-77060c2ff497",
#                     "reverse_dns": true,
#                     "attributes": {
#                         "userdata": {},
#                         "network": {
#                             "nimbula_vcable-eth0": {
#                                 "vethernet_id": "0",
#                                 "vethernet": "/oracle/public/default",
#                                 "address": [
#                                     "c6:b0:ef:d3:23:c1",
#                                     "10.29.232.178"
#                                 ],
#                                 "model": "",
#                                 "vethernet_type": "vlan",
#                                 "id": "/Compute-omcsservicedom1/mageshwaran.k.kasi@oracle.com/dcf683e7-9452-4b59-8293-445bd2e81568",
#                                 "dhcp_options": []
#                             }
#                         },
#                         "oracle_metadata": {
#                             "v1": {
#                                 "object": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch/e5a17f32-fbf1-4e4c-9ead-f504df6a16f5",
#                                 "orchestration": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch"
#                             }
#                         },
#                         "sshkeys": [
#                             "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJOMGs6B9xrWJeclCtIHewPYG7pu6nRCnSgaRlYtez1fehJr5POWDIibZpoJbR7XUlU9YiDyAokfEXUVS2aJaltphxj+JAmaXFgvS+zbhqeLtOzIHEyJJycwotvD0CFmNYerMmtihJtiCZHynrorPienfpqg3ULvbG69wWh2S19oGhqa30zXrWO0G96y2Xw1TxYJ1PHpY18HR+ouObzVrOdpDjlfia2TyrLUSCW3O2Cd5Fowtkw6IWPrTdJBU7AeeNwzto3hOn+Rx3KQv5BZuN6cBcHqvP4XVXFkujJNlXv0Qvo/hPXnD670dM2GcEx2VB9ztVchSW0aB0F4erRstovqMH0MWKonfYUTk8Ggfg/psz1CHANB4U8IUpChJ8WaDlnx9ENK3NLY7T87rp34dkSwcvQZfxuU6rQdAiaalvdain1hV3GE0Fa1ajo1P5Kdby3qvHkF6HgaWJQEpUM2/YYOVHBi78U6Cs927Cklhc/u++IPjUCKDWeovh+PILNOQ5w6Y3pZq/ORzOK5UIOH2XAqrH7ep4lLEJBDkpSLNfKmLq7cUrFVh3A9Qx4WRl2yD6XhhvPKRfO7qcjLiGLVfWBnQTeKEvB2i5OrfpdvlBvvkYHIhp4eZi76dGkl83aXHbkW8fifysMDX4/KwhHlN9ZpV3hDGqpj+m6ETjxWRs5Q=="
#                         ],
#                         "dns": {
#                             "domain": "compute-omcsservicedom1.oraclecloud.internal.",
#                             "hostname": "omcsbabhcbhosv.compute-omcsservicedom1.oraclecloud.internal.",
#                             "nimbula_vcable-eth0": "omcsbabhcbhosv.compute-omcsservicedom1.oraclecloud.internal."
#                         },
#                         "nimbula_orchestration": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch"
#                     },
#                     "boot_order": [
#                         1
#                     ]
#                 }
#             },
#             "time_created": "2017-11-21T23:55:32Z",
#             "orchestration": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch",
#             "user": "/Compute-omcsservicedom1/mageshwaran.k.kasi@oracle.com",
#             "type": "Instance",
#             "name": "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-ANSIBLE-MT001-orch/e5a17f32-fbf1-4e4c-9ead-f504df6a16f5"
#         }
#     ],
#     "user": "/Compute-omcsservicedom1/mageshwaran.k.kasi@oracle.com",
#     "version": 1,
#     "id": "14ae8c02-fb1e-447d-a238-e9f58fac014e",
#     "desired_state": "active",
#     "_paasResource": false,
#     "_personalResource": false
# }
#
#
# [
#     "relationships": [],
#     "status": "ready",
#     "account": "/Compute-omcsservicedom1/default",
#     "description": "EBSOTEST-MT001 assembly",
#     "schedule": {
#         "start_time": "2017-12-05T15:45:21Z",
#         "stop_time": null
#     },
#     "uri": "https://api-uscom-central-1.compute.usdc2.oraclecloud.com/orchestration/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001-orch",
#     "oplans": [
#         {
#             "status": "ready",
#             "info": {
#                 "errors": {}
#             },
#             "obj_type": "launchplan",
#             "ha_policy": "active",
#             "label": "EBSOTEST-MT001",
#             "objects": [
#                 {
#                     "instances": [
#                         {
#                             "networking": {
#                                 "eth0": {
#                                     "seclists": [
#                                         "/Compute-omcsservicedom1/orchestration/SL-OMCS-TEST"
#                                     ],
#                                     "nat": "ipreservation:/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001-eip",
#                                     "dns": [
#                                         "omcsbdcqpgknrg"
#                                     ]
#                                 }
#                             },
#                             "name": "/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001/d1c2c847-7be9-4195-878e-f27cd3f76083",
#                             "placement_requirements": [],
#                             "boot_order": [
#                                 1
#                             ],
#                             "ip": "10.22.136.162",
#                             "start_time": "2017-12-05T15:45:25Z",
#                             "hostname": "omcsbdcqpgknrg.compute-omcsservicedom1.oraclecloud.internal.",
#                             "image_metadata_bag": "/oracle/machineimage_metadata/457a7556602e43eca380d29baff41833",
#                             "uri": null,
#                             "label": "EBSOTEST-MT001",
#                             "reverse_dns": true,
#                             "shape": "oc1m",
#                             "state": "running",
#                             "storage_attachments": [
#                                 {
#                                     "volume": "/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001-boot",
#                                     "index": 1
#                                 }
#                             ],
#                             "attributes": {
#                                 "userdata": {},
#                                 "nimbula_orchestration": "/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001-orch"
#                             },
#                             "imagelist": "/Compute-omcsservicedom1/jason.rothstein@oracle.com/OPC_OL6_8_X86_64_EBS_OS_VM_12202016",
#                             "sshkeys": [
#                                 "/Compute-omcsservicedom1/orchestration/US2-USCOMCENTRAL1-OMCS-TEST-MT001-key"
#                             ],
#                             "tags": [
#                                 "EBSTEST",
#                                 "omcsbdcqpgknrg"
#                             ]
#                         }
#                     ]
#                 }
#             ],
#             "status_timestamp": "2017-12-05T15:47:47Z"
#         }
#     ],
#     "info": {
#         "errors": {}
#     },
#     "user": "/Compute-omcsservicedom1/neeraj.k.kumar@oracle.com",
#     "status_timestamp": "2017-12-12T08:06:02Z",
#     "name": "/Compute-omcsservicedom1/orchestration/EBSOTEST-MT001-orch",
#     "_paasResource": false,
#     "_personalResource": false
# ]