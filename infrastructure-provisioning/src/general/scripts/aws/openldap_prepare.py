#!/usr/bin/python

# *****************************************************************************
#
# Copyright (c) 2017, EPAM SYSTEMS INC
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
    local_log_filename = "{}_{}.log".format(os.environ['conf_resource'], os.environ['request_id'])
    local_log_filepath = "/logs/openldap/" + local_log_filename
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s',
                        level=logging.DEBUG,
                        filename=local_log_filepath)

    try:
        logging.info('[CREATE AWS CONFIG FILE]')
        print '[CREATE AWS CONFIG FILE]'
        if not create_aws_config_files(generate_full_config=True):
            logging.info('Unable to create configuration')
            append_result("Unable to create configuration")
            traceback.print_exc()
            sys.exit(1)
    except:
        sys.exit(1)

    print 'Generating infrastructure names and tags'
    openldap_conf = dict()
    openldap_conf['service_base_name'] = os.environ['conf_service_base_name']
    openldap_conf['key_name'] = os.environ['conf_key_name']
    openldap_conf['public_subnet_id'] = os.environ['aws_subnet_id']
    openldap_conf['vpc_id'] = os.environ['aws_vpc_id']
    openldap_conf['region'] = os.environ['aws_region']
    openldap_conf['ami_id'] = get_ami_id(os.environ['aws_' + os.environ['conf_os_family'] + '_ami_name'])
    openldap_conf['instance_size'] = os.environ['aws_openldap_instance_size']
    openldap_conf['sg_ids'] = os.environ['aws_security_groups_ids']
    openldap_conf['instance_name'] = openldap_conf['service_base_name'] + '-openldap'
    openldap_conf['tag_name'] = openldap_conf['service_base_name'] + '-Tag'
    openldap_conf['policy_name'] = openldap_conf['service_base_name'].lower().replace('-', '_') + '-openldap-Policy'
    openldap_conf['openldap_security_group_name'] = openldap_conf['instance_name'] + '-SG'
    openldap_conf['private_subnet_prefix'] = os.environ['aws_private_subnet_prefix']
    openldap_conf['openldap_sg_description'] = openldap_conf['service_base_name'] + ' OpenLDAP SG'
    openldap_conf['ssn_public_ip'] = get_instance_ip_address(openldap_conf['tag_name'],
                                                             openldap_conf['service_base_name'] + '-ssn').get('Public')
    openldap_conf['ssn_private_ip'] = get_instance_ip_address(openldap_conf['tag_name'],
                                                              openldap_conf['service_base_name'] + '-ssn').get('Private')

    print "Will deploy ldap as following: " + \
          json.dumps(openldap_conf, sort_keys=True, indent=4, separators=(',', ': '))
    logging.info(json.dumps(openldap_conf))

    try:
        logging.info('[CREATE SUBNET]')
        print '[CREATE SUBNET]'
        params = "--vpc_id '{}' --infra_tag_name {} --infra_tag_value {} --prefix {}" \
            .format(openldap_conf['vpc_id'], openldap_conf['tag_name'], openldap_conf['service_base_name'],
                    openldap_conf['private_subnet_prefix'])
        try:
            local("~/scripts/{}.py {}".format('common_create_subnet', params))
        except:
            traceback.print_exc()
            raise Exception
    except Exception as err:
        append_result("Failed to create subnet.", str(err))
        sys.exit(1)

    tag = {"Key": openldap_conf['tag_name'], "Value": "{}-subnet".format(openldap_conf['service_base_name'])}
    openldap_conf['private_subnet_cidr'] = get_subnet_by_tag(tag)
    print 'NEW SUBNET CIDR CREATED: {}'.format(openldap_conf['private_subnet_cidr'])

    try:
        logging.info('[CREATE SECURITY GROUP FOR OPENLDAP NODE]')
        print '[CREATE SECURITY GROUPS FOR OPENLDAP]'
        sg_rules_template = [
            {
                'PrefixListIds': [],
                'FromPort': 22,
                'IpRanges': [{'CidrIp': '{}/32'.format(openldap_conf['ssn_public_ip'])},
                             {'CidrIp': '{}/32'.format(openldap_conf['ssn_private_ip'])}
                             ],
                'ToPort': 22,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            },
            {
                'PrefixListIds': [],
                'FromPort': 389,
                'IpRanges': [{'CidrIp': '{}/32'.format(openldap_conf['ssn_public_ip'])},
                             {'CidrIp': '{}/32'.format(openldap_conf['ssn_private_ip'])}
                             ],
                'ToPort': 389,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            }
        ]
        sg_rules_template_egress = [
            {
                'PrefixListIds': [],
                'FromPort': 22,
                'IpRanges': [{'CidrIp': '{}/32'.format(openldap_conf['ssn_public_ip'])},
                             {'CidrIp': '{}/32'.format(openldap_conf['ssn_private_ip'])}
                             ],
                'ToPort': 22,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            },
            {
                'PrefixListIds': [],
                'FromPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                'ToPort': 80,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            },
            {
                'PrefixListIds': [],
                'FromPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                'ToPort': 443,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            },
            {
                'PrefixListIds': [],
                'FromPort': 389,
                'IpRanges': [{'CidrIp': '{}/32'.format(openldap_conf['ssn_public_ip'])},
                             {'CidrIp': '{}/32'.format(openldap_conf['ssn_private_ip'])}
                             ],
                'ToPort': 389,
                'IpProtocol': 'tcp',
                'UserIdGroupPairs': [],
                'Ipv6Ranges': []
            }
        ]
        params = "--name '{}' --description '{}' --vpc_id '{}' --security_group_rules '{}' --infra_tag_name '{}' "\
                 "--infra_tag_value '{}' --egress '{}' --force '{}' --resource '{}'"\
                 .format(openldap_conf['openldap_security_group_name'], openldap_conf['openldap_sg_description'],
                         openldap_conf['vpc_id'], json.dumps(sg_rules_template), openldap_conf['service_base_name'],
                         openldap_conf['instance_name'], json.dumps(sg_rules_template_egress), True, 'openldap')
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
        sys.exit(1)

    try:
        logging.info('[CREATE OPENLDAP INSTANCE]')
        print '[CREATE openldap INSTANCE]'
        openldap_group_id = openldap_conf['sg_ids'] + ',' + \
                            check_security_group(openldap_conf['openldap_security_group_name'])
        params = "--node_name {} --ami_id {} --instance_type {} --key_name {} --security_group_ids {} \
                 --subnet_id {} --infra_tag_name {} --instance_class {} \
                 --infra_tag_value {}".format(openldap_conf['instance_name'], openldap_conf['ami_id'],
                                              openldap_conf['instance_size'], openldap_conf['key_name'],
                                              openldap_group_id, openldap_conf['public_subnet_id'],
                                              openldap_conf['tag_name'], openldap_conf['service_base_name'], 
                                              openldap_conf['instance_name'])
        try:
            local("~/scripts/{}.py {}".format('common_create_instance', params))
        except:
            traceback.print_exc()
            raise Exception

    except Exception as err:
        append_result("Failed to create instance.", str(err))
        remove_sgroups(openldap_conf['instance_name'])
        sys.exit(1)

    try:
        if os.environ['conf_os_family'] == 'debian':
            initial_user = 'ubuntu'
            sudo_group = 'sudo'
        if os.environ['conf_os_family'] == 'redhat':
            initial_user = 'ec2-user'
            sudo_group = 'wheel'

        logging.info('[CREATING DLAB SSH USER]')
        print('[CREATING DLAB SSH USER]')
        params = "--hostname {} --keyfile {} --initial_user {} --os_user {} --sudo_group {}".format\
            (get_instance_hostname(openldap_conf['tag_name'], openldap_conf['instance_name']),
             '{}{}.pem'.format(os.environ['conf_key_dir'], os.environ['conf_key_name']),
             initial_user, os.environ['conf_os_user'], sudo_group)

        try:
            local("~/scripts/{}.py {}".format('create_ssh_user', params))
        except:
            traceback.print_exc()
            raise Exception
    except Exception as err:
        append_result("Failed creating ssh user 'dlab'.", str(err))
        remove_ec2(openldap_conf['tag_name'], openldap_conf['instance_name'])
        sys.exit(1)
