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

COPY zeppelin/ /root/
COPY general/scripts/${CLOUD}/zeppelin_* /root/scripts/
COPY general/scripts/os/* /root/scripts/
COPY zeppelin/scripts/create_configs.py /root/scripts/
COPY general/lib/os/${OS}/notebook_lib.py /usr/lib/python2.7/dlab/notebook_lib.py
COPY general/templates/${CLOUD}/emr_interpreter_livy.json /root/templates/
COPY general/templates/${CLOUD}/emr_interpreter_spark.json /root/templates/
COPY general/templates/os/notebook_spark-defaults_local.conf /root/templates/
COPY general/templates/os/${OS}/ungit.service /root/templates/
COPY general/files/os/notebook_local_jars.tar.gz /root/files/

RUN chmod a+x /root/fabfile.py; \
    chmod a+x /root/scripts/*

