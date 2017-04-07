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
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--bucket', type=str, default='')
parser.add_argument('--emr_version', type=str, default='')
parser.add_argument('--region', type=str, default='')
parser.add_argument('--user_name', type=str, default='')
parser.add_argument('--cluster_name', type=str, default='')
args = parser.parse_args()


if __name__ == "__main__":
    spark_def_path = "/usr/lib/spark/conf/spark-defaults.conf"
    spark_def_path_line1 = local("cat " + spark_def_path + " | grep spark.driver.extraClassPath | awk '{print $2}' | "
                                 "sed 's/^:// ; s~jar:~jar ~g; s~/\*:~/\* ~g; s~:~/\* ~g'")
    spark_def_path_line2 = local("cat " + spark_def_path + " | grep spark.driver.extraLibraryPath | awk '{print $2}' | "
                                                           "sed 's/^:// ; s~jar:~jar ~g; s~/\*:~/\* ~g; s~:\|$~/\* ~g'")
    if args.region == 'us-east-1':
        endpoint = "https://s3.amazonaws.com"
    else:
        endpoint = "https://s3-{}.amazonaws.com".format(args.region)
    local('touch /tmp/python_version')
    python_ver = local("python3.5 -V 2>/dev/null | awk '{print $2}'", capture=True)
    if python_ver != '':
        local('echo {} > /tmp/python_version'.format(python_ver))
    else:
        python_ver = local("python3.4 -V 2>/dev/null | awk '{print $2}'", capture=True)
        local('echo {} > /tmp/python_version'.format(python_ver))
    local('/bin/tar -zhcvf /tmp/jars.tar.gz --no-recursion --absolute-names --ignore-failed-read /usr/lib/hadoop/* {} '
          '{} /usr/lib/hadoop/client/*'.format(spark_def_path_line1, spark_def_path_line2))
    local('/bin/tar -zhcvf /tmp/spark.tar.gz -C /usr/lib/ spark')
    local('md5sum /tmp/jars.tar.gz > /tmp/jars-checksum.chk')
    local('md5sum /tmp/spark.tar.gz > /tmp/spark-checksum.chk')
    local('aws s3 cp /tmp/jars.tar.gz s3://{}/jars/{}/ --endpoint-url {} --region {}'.
          format(args.bucket, args.emr_version, endpoint, args.region))
    local('aws s3 cp /tmp/jars-checksum.chk s3://{}/jars/{}/ --endpoint-url {} --region {}'.
          format(args.bucket, args.emr_version, endpoint, args.region))
    local('aws s3 cp {} s3://{}/{}/{}/ --endpoint-url {} --region {}'.
          format(spark_def_path, args.bucket, args.user_name, args.cluster_name, endpoint, args.region))
    local('aws s3 cp /tmp/python_version s3://{}/{}/{}/ --endpoint-url {} --region {}'.
          format(args.bucket, args.user_name, args.cluster_name, endpoint, args.region))
    local('aws s3 cp /tmp/spark.tar.gz s3://{}/{}/{}/ --endpoint-url {} --region {}'.
          format(args.bucket, args.user_name, args.cluster_name, endpoint, args.region))
    local('aws s3 cp /tmp/spark-checksum.chk s3://{}/{}/{}/ --endpoint-url {} --region {}'.
          format(args.bucket, args.user_name, args.cluster_name, endpoint, args.region))