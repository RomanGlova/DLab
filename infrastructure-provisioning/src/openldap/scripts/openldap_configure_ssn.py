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

from fabric.api import *
from dlab.meta_lib import *
import os

ssn_host = get_instance_hostname(os.environ['conf_service_base_name'] + '-Tag',
                                 os.environ['conf_service_base_name'] + '-ssn')

if os.environ['deploy_ldap'].lower() == 'false':
    ldap_host = os.environ['ldap_host']
else:
    ldap_host = get_instance_hostname(os.environ['conf_service_base_name'] + '-Tag',
                                      os.environ['conf_service_base_name'] + '-openldap')

ldap_domain = os.environ['ldap_domain'].replace('.', ',dc=')
ldap_host_user = os.environ['conf_os_user']
ldap_adm_user = 'cn=' + os.environ['ldap_adm_user'] + ',dc=dlab,dc=' + ldap_domain
ldap_adm_pass = os.environ['ldap_adm_pass']

env['connection_attempts'] = 100
env.key_filename = '{}{}.pem'.format(os.environ['conf_key_dir'], os.environ['conf_key_name'])
env.host_string = '{}@{}'.format(ldap_host_user, ssn_host)

with cd('/opt/dlab/conf/'):
    run('sed -i "s/LDAP_HOST/' + ldap_host + '/g" security.yml')
    run('sed -i "s/LDAP_USER/' + ldap_adm_user + '/g" security.yml')
    run("sed -i 's/LDAP_PASS/" + ldap_adm_pass + "/g' security.yml")

sudo('supervisorctl restart all')
run('echo "SSN node: ' + ssn_host + ' configured to use OpenLdap node: ' + ldap_host + '"')
print('SSN node: ' + ssn_host + ' configured to use OpenLdap node: ' + ldap_host)
