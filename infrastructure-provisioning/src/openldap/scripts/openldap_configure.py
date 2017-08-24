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
from fabric.contrib.files import exists
from dlab.meta_lib import *
import os
import sys
import hashlib
import uuid

ldap_host = get_instance_hostname(os.environ['conf_service_base_name'] + '-Tag',
                                  os.environ['conf_service_base_name'] + '-openldap')
ldap_host_user = os.environ['conf_os_user']
ldap_adm_user = os.environ['ldap_adm_user']
ldap_adm_pass = os.environ['ldap_adm_pass']
ldap_domain = os.environ['ldap_domain'].replace('.', ',dc=')

env['connection_attempts'] = 100
env.key_filename = '{}{}.pem'.format(os.environ['conf_key_dir'], os.environ['conf_key_name'])
env.host_string = '{}@{}'.format(ldap_host_user, ldap_host)


def make_ldap_secret(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    """
    salt = os.urandom(4)
    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)
    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()
    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)
    return tagged_digest_salt


def configure_openldap(os_user, adm_user, adm_pass, domain):
    if not exists('/home/' + os_user + '/.ensure_dir/openldap_configured'):
        try:
            if os.environ['conf_os_family'] == 'debian':
                olc_database = '{1}mdb'
            if os.environ['conf_os_family'] == 'redhat':
                olc_database = '{2}hdb'
            sudo('cat << EOF | ldapmodify -Y EXTERNAL -H ldapi://\n'
                 'dn: olcDatabase=' + olc_database + ',cn=config\n'
                 'changetype: modify\n'
                 'replace: olcSuffix\n'
                 'olcSuffix: dc=dlab,dc=' + domain + '\n\n'
                 'dn: olcDatabase=' + olc_database + ',cn=config\n'
                 'changetype: modify\n'
                 'replace: olcRootDN\n'
                 'olcRootDN: cn=' + adm_user + ',dc=dlab,dc=' + domain + '\n\n'
                 'dn: olcDatabase=' + olc_database + ',cn=config\n'
                 'changetype: modify\n'
                 'replace: olcRootPW\n'
                 'olcRootPW: ' + make_ldap_secret(adm_pass) + '\nEOF')

            # Adding root entry
            sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                 'dn: dc=dlab,dc=' + domain + '\n'
                 'dc: dlab\n'
                 'o: dlab.' + os.environ['ldap_domain'] + ' LDAP Server\n'
                 'description: Root entry for dlab.' + os.environ['ldap_domain'] + '\n'
                 'objectClass: top\n'
                 'objectclass: dcObject\n'
                 'objectclass: organization\nEOF')

            # Adding organizationalUnit "People" to ldap
            sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                 'dn: ou=People,dc=dlab,dc=' + domain + '\n'
                 'objectClass: organizationalUnit\n'
                 'ou: People\nEOF')

            # Adding organizationalUnit "Groups" to ldap
            sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                 'dn: ou=Groups,dc=dlab,dc=' + domain + '\n'
                 'objectClass: organizationalUnit\n'
                 'ou: Groups\nEOF')

            sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                 'dn: cn=' + adm_user + ',dc=dlab,dc=' + domain + '\n'
                 'objectClass: organizationalRole\n'
                 'cn: ' + adm_user + '\n'
                 'description: LDAP Manager\nEOF')

            # If defined, creating dlab users group and test user in ldap
            if os.environ['ldap_test_user'].lower() == 'true':
                # Adding Group
                sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                     'dn: cn=dlab_users,ou=Groups,dc=dlab,dc=' + domain + '\n'
                     'cn: dlab_users\n'
                     'gidNumber: 5000\n'
                     'objectclass: top\n'
                     'objectclass: posixGroup\nEOF')
                # Adding test user
                user_pass = uuid.uuid4().hex
                sudo('cat << EOF | ldapadd -x -w "' + adm_pass + '" -D "cn=' + adm_user + ',dc=dlab,dc=' + domain + '"\n'
                     'dn: uid=dlab,ou=People,dc=dlab,dc=' + domain + '\n'
                     'objectClass: shadowAccount\n'
                     'objectClass: inetOrgPerson\n'
                     'objectClass: top\n'
                     'objectClass: posixAccount\n'
                     'cn: Dlab User\n'
                     'gidNumber: 5000\n'
                     'homeDirectory: /home/dlab_user\n'
                     'sn: User\n'
                     'uid: dlab\n'
                     'uidNumber: 52000\n'
                     'displayName: Dlab User\n'
                     'gecos: Dlab User\n'
                     'givenName: Dlab\n'
                     'loginShell: /bin/nologin\n'
                     'mail: dlab@example.com\n'
                     'shadowExpire: 99999\n'
                     'shadowFlag: 0\n'
                     'shadowInactive: 99999\n'
                     'shadowLastChange: 12011\n'
                     'shadowMax: 99999\n'
                     'shadowMin: 0\n'
                     'shadowWarning: 0\n'
                     'userPassword: ' + make_ldap_secret(user_pass) + '\nEOF')

            sudo('ldapwhoami -H ldap:// -x')
            sudo('touch /home/{}/.ensure_dir/openldap_configured'.format(os_user))
            print('OpenLDAP configured!')
            if os.environ['ldap_test_user'].lower() == 'true':
                print('OpenLDAP test username: dlab')
                print('OpenLDAP test password: ' + user_pass)
        except:
            sys.exit(1)
    else:
        try:
            print('OpenLDAP already configured!')
        except:
            sys.exit(1)

if __name__ == '__main__':
    configure_openldap(ldap_host_user, ldap_adm_user, ldap_adm_pass, ldap_domain)
