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

import sys
from dlab.fab import *
from dlab.meta_lib import *
from dlab.actions_lib import *
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--elastic_ip', type=str, default='')
parser.add_argument('--ssn_id', type=str)
args = parser.parse_args()

if __name__ == "__main__":
    local_log_filename = "{}_{}.log".format(os.environ['conf_resource'], os.environ['request_id'])
    local_log_filepath = "/logs/" + os.environ['conf_resource'] +  "/" + local_log_filename
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s',
                        level=logging.DEBUG,
                        filename=local_log_filepath)
    try:
        if args.elastic_ip == 'None':
            print "Allocating Elastic IP"
            allocation_id = allocate_elastic_ip()
        else:
            allocation_id = get_allocation_id_by_elastic_ip(args.elastic_ip)

        print "Associating Elastic IP to SSN"
        associate_elastic_ip(args.ssn_id, allocation_id)
    except:
        sys.exit(1)
