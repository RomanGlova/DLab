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
import os
import sys
import hashlib

ldap_host = os.environ['ldap_host']
ldap_host_user = os.environ['ldap_host_user']
ldap_adm_user = os.environ['ldap_adm_user']
ldap_adm_pass = os.environ['ldap_adm_pass']
ldap_domain = os.environ['ldap_domain'].replace('.', ',dc=')

env['connection_attempts'] = 100
env.key_filename = os.environ['key_filename']
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


def configure_openldap(os_user, ldap_adm_user, ldap_adm_pass, ldap_domain):
    if not exists('/home/' + os_user + '/.ensure_dir/openldap_configured'):
        try:
            sudo('yum -y install openldap compat-openldap openldap-clients openldap-servers\ openldap-servers-sql '
                 'openldap-devel')
            sudo('systemctl start slapd.service')
            sudo('systemctl enable slapd.service')
            sudo('cat << EOF | ldapmodify -Y EXTERNAL -H ldapi://\n'
                 'changetype: modify\n'
                 'replace: olcSuffix\n'
                 'olcSuffix: dc=dlab,dc=' + ldap_domain + '\n\n'
                 'dn: olcDatabase={2}hdb,cn=config\n'
                 'changetype: modify\n'
                 'replace: olcRootDN\n'
                 'olcRootDN: cn=' + ldap_adm_user + ',dc=dlab,dc=' + ldap_domain + '\n\n'
                 'dn: olcDatabase={2}hdb,cn=config\n'
                 'changetype: modify\n'
                 'replace: olcRootPW\n'
                 'olcRootPW: ' + make_ldap_secret(ldap_adm_pass) + '\nEOF')
            sudo('cat << EOF | ldapmodify -Y EXTERNAL -H ldapi://\n'
                 'dn: olcDatabase={1}monitor,cn=config\n'
                 'changetype: modify\n'
                 'replace: olcAccess\n'
                 'olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" read by '
                 'dn.base="cn=' + ldap_adm_user + ',dc=dlab,dc=' + ldap_domain + '" read by * none\nEOF')

            # Copy the sample database configuration file to /var/lib/ldap and update the file permissions.
            sudo('cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG')
            sudo('chown ldap:ldap /var/lib/ldap/*')

            # Add the cosine and nis LDAP schemas.
            sudo('ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif')
            sudo('ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif')
            sudo('ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif')

            sudo('cat << EOF | ldapadd -x -W -D "cn=' + ldap_adm_user + ',dc=dlab,dc=' + ldap_domain + '"\n'
                 'dn: dc=dlab,dc=' + ldap_domain + '\n'
                 'dc: dlab\n'
                 'objectClass: top\n'
                 'objectClass: domain\n\n'
                 'dn: cn=' + ldap_adm_user + ',dc=dlab,dc=' + ldap_domain + '\n'
                 'objectClass: organizationalRole\n'
                 'cn: ' + ldap_adm_user + '\n'
                 'description: LDAP Manager\nEOF')

            sudo('ldapwhoami -H ldap:// -x')
            sudo('touch /home/{}/.ensure_dir/openldap_configured'.format(os_user))
        except:
            sys.exit(1)
    else:
        try:
            print('OpenLDAP already configured!')
        except:
            sys.exit(1)

if __name__ == '__main__':
    configure_openldap(ldap_host_user, ldap_adm_user, ldap_adm_pass, ldap_domain)
