#!/usr/bin/python

# *****************************************************************************
#
# Copyright (c) 2016, EPAM SYSTEMS INC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ******************************************************************************

import json
from dlab.fab import *
from dlab.meta_lib import *
import sys, time, os
from dlab.actions_lib import *
import traceback


if __name__ == "__main__":
    local_log_filename = "{}_{}_{}.log".format(os.environ['conf_resource'], os.environ['openldap_user_name'],
                                               os.environ['request_id'])
    local_log_filepath = "/logs/openldap/" + local_log_filename
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s',
                        level=logging.DEBUG,
                        filename=local_log_filepath)

    create_aws_config_files()
    print 'Generating infrastructure names and tags'
    openldap_conf = dict()
    openldap_conf['service_base_name'] = os.environ['conf_service_base_name']
    openldap_conf['key_name'] = os.environ['conf_key_name']
    openldap_conf['user_keyname'] = os.environ['openldap_user_name']
    openldap_conf['public_subnet_id'] = os.environ['aws_subnet_id']
    openldap_conf['vpc_id'] = os.environ['aws_vpc_id']
    openldap_conf['region'] = os.environ['aws_region']
    openldap_conf['ami_id'] = get_ami_id(os.environ['aws_' + os.environ['conf_os_family'] + '_ami_name'])
    openldap_conf['instance_size'] = os.environ['aws_openldap_instance_size']
    openldap_conf['sg_ids'] = os.environ['aws_security_groups_ids']
    openldap_conf['instance_name'] = openldap_conf['service_base_name'] + "-" + os.environ['openldap_user_name'] + '-openldap'
    openldap_conf['tag_name'] = openldap_conf['service_base_name'] + '-Tag'
    openldap_conf['bucket_name'] = (openldap_conf['service_base_name'] + "-" + os.environ['openldap_user_name'] + '-bucket').lower().replace('_', '-')
    openldap_conf['ssn_bucket_name'] = (openldap_conf['service_base_name'] + "-ssn-bucket").lower().replace('_', '-')
    openldap_conf['shared_bucket_name'] = (openldap_conf['service_base_name'] + "-shared-bucket").lower().replace('_', '-')
    openldap_conf['role_name'] = openldap_conf['service_base_name'].lower().replace('-', '_') + "-" + os.environ['openldap_user_name'] + '-openldap-Role'
    openldap_conf['role_profile_name'] = openldap_conf['service_base_name'].lower().replace('-', '_') + "-" + os.environ['openldap_user_name'] + '-openldap-Profile'
    openldap_conf['policy_name'] = openldap_conf['service_base_name'].lower().replace('-', '_') + "-" + os.environ['openldap_user_name'] + '-openldap-Policy'
    openldap_conf['openldap_security_group_name'] = openldap_conf['instance_name'] + '-SG'
    openldap_conf['private_subnet_prefix'] = os.environ['aws_private_subnet_prefix']

    # FUSE in case of absence of user's key
    fname = "/root/keys/{}.pub".format(openldap_conf['user_keyname'])
    if not os.path.isfile(fname):
        print "USERs PUBLIC KEY DOES NOT EXIST in {}".format(fname)
        sys.exit(1)

    print "Will create exploratory environment with edge node as access point as following: " + \
          json.dumps(openldap_conf, sort_keys=True, indent=4, separators=(',', ': '))
    logging.info(json.dumps(openldap_conf))

    try:
        logging.info('[CREATE SUBNET]')
        print '[CREATE SUBNET]'
        params = "--vpc_id '{}' --infra_tag_name {} --infra_tag_value {} --username {} --prefix {}" \
                 .format(openldap_conf['vpc_id'], openldap_conf['tag_name'], openldap_conf['service_base_name'],
                         os.environ['openldap_user_name'], openldap_conf['private_subnet_prefix'])
        try:
            local("~/scripts/{}.py {}".format('common_create_subnet', params))
        except:
            traceback.print_exc()
            raise Exception
    except Exception as err:
        append_result("Failed to create subnet.", str(err))
        sys.exit(1)

    tag = {"Key": openldap_conf['tag_name'], "Value": "{}-{}-subnet".format(openldap_conf['service_base_name'], os.environ['openldap_user_name'])}
    openldap_conf['private_subnet_cidr'] = get_subnet_by_tag(tag)
    print 'NEW SUBNET CIDR CREATED: {}'.format(openldap_conf['private_subnet_cidr'])

    try:
        logging.info('[CREATE OPENLDAP ROLES]')
        print '[CREATE OPENLDAP ROLES]'
        params = "--role_name {} --role_profile_name {} --policy_name {} --region {}" \
                 .format(openldap_conf['role_name'], openldap_conf['role_profile_name'],
                         openldap_conf['policy_name'], os.environ['aws_region'])
        try:
            local("~/scripts/{}.py {}".format('common_create_role_policy', params))
        except:
            traceback.print_exc()
            raise Exception
    except Exception as err:
        append_result("Failed to creating roles.", str(err))
        sys.exit(1)

     try:
        logging.info('[CREATE SECURITY GROUP FOR OPENLDAP NODE]')
        print '[CREATE SECURITY GROUPS FOR OPENLDAP]'
        sg_rules_template = [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": openldap_conf['private_subnet_cidr']}],
                "UserIdGroupPairs": [], "PrefixListIds": []
            },
            {
                "PrefixListIds": [],
                "FromPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "ToPort": 22, "IpProtocol": "tcp", "UserIdGroupPairs": []
            },
            {
                "PrefixListIds": [],
                "FromPort": 389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "ToPort": 389, "IpProtocol": "tcp", "UserIdGroupPairs": []
            }
        ]
        sg_rules_template_egress = [
            {
                "PrefixListIds": [],
                "FromPort": 389,
                "IpRanges": [{"CidrIp": openldap_conf['private_subnet_cidr']}],
                "ToPort": 389, "IpProtocol": "tcp", "UserIdGroupPairs": []
            }
        ]
        params = "--name {} --vpc_id {} --security_group_rules '{}' --infra_tag_name {} --infra_tag_value {} --egress '{}' --force {} --resource {}".\
            format(openldap_conf['openldap_security_group_name'], openldap_conf['vpc_id'], json.dumps(sg_rules_template),
                   openldap_conf['service_base_name'], openldap_conf['instance_name'], json.dumps(sg_rules_template_egress),
                   True, 'openldap')
        try:
            local("~/scripts/{}.py {}".format('common_create_security_group', params))
        except Exception as err:
            traceback.print_exc()
            append_result("Failed creating security group for openldap node.", str(err))
            raise Exception

        with hide('stderr', 'running', 'warnings'):
            print 'Waiting for changes to propagate'
            time.sleep(10)
    except:
        remove_all_iam_resources('openldap', os.environ['openldap_user_name'])
        sys.exit(1)

    try:
        logging.info('[CREATE OPENLDAP INSTANCE]')
        print '[CREATE openldap INSTANCE]'
        params = "--node_name {} --ami_id {} --instance_type {} --key_name {} --security_group_ids {} " \
                 "--subnet_id {} --iam_profile {} --infra_tag_name {} --infra_tag_value {}" \
            .format(openldap_conf['instance_name'], openldap_conf['ami_id'], openldap_conf['instance_size'], openldap_conf['key_name'],
                    openldap_group_id, openldap_conf['public_subnet_id'], openldap_conf['role_profile_name'],
                    openldap_conf['tag_name'], openldap_conf['instance_name'])
        try:
            local("~/scripts/{}.py {}".format('common_create_instance', params))
        except:
            traceback.print_exc()
            raise Exception

    except Exception as err:
        append_result("Failed to create instance.", str(err))
        remove_all_iam_resources('openldap', os.environ['openldap_user_name'])
        remove_sgroups(openldap_conf['instance_name'])
        remove_s3('openldap', os.environ['openldap_user_name'])
        sys.exit(1)
