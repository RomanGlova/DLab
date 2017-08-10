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

FROM docker.dlab-base:latest

ARG OS
ARG CLOUD

COPY openldap/fabfile.py /root/
COPY openldap/scripts/openldap_prepare.py /root/scripts/openldap_prepare.py
COPY openldap/scripts/os/${OS}/openldap_install.py /root/scripts/openldap_install.py
COPY openldap/scripts/openldap_configure.py /root/scripts/openldap_configure.py
COPY openldap/scripts/openldap_terminate.py /root/scripts/openldap_terminate.py

RUN chmod a+x /root/fabfile.py; \
    chmod a+x /root/scripts/*

RUN mkdir /project_tree
COPY . /project_tree

