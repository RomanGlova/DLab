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

from fabric.api import *
from fabric.contrib.files import exists
from dlab.meta_lib import *
import sys
import os

ldap_host = get_instance_hostname(os.environ['conf_service_base_name'] + '-Tag',
                                  os.environ['conf_service_base_name'] + '-openldap')
ldap_host_user = os.environ['conf_os_user']

env['connection_attempts'] = 100
env.key_filename = '{}{}.pem'.format(os.environ['conf_key_dir'], os.environ['conf_key_name'])
env.host_string = '{}@{}'.format(ldap_host_user, ldap_host)


def install_openldap(os_user):
    if not exists('/home/' + os_user + '/.ensure_dir/openldap_ensured'):
        try:
            sudo('apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y slapd ldap-utils')
            sudo('ufw allow ldap')
            sudo('touch /home/{}/.ensure_dir/openldap_ensured'.format(os_user))
        except:
            sys.exit(1)
    else:
        try:
            print('OpenLDAP already installed!')
        except:
            sys.exit(1)

if __name__ == '__main__':
    install_openldap(ldap_host_user)
