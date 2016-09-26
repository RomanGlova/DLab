#!/usr/bin/python
import argparse
import json
from dlab.aws_actions import *
from dlab.aws_meta import *


parser = argparse.ArgumentParser()
parser.add_argument('--bucket_name', type=str, default='dsa-test-bucket')
parser.add_argument('--infra_tag_name', type=str, default='BDCC-DSA-test-infra')
parser.add_argument('--infra_tag_value', type=str, default='tmp')
args = parser.parse_args()


if __name__ == "__main__":
    tag = {"Key": args.infra_tag_name, "Value": args.infra_tag_value}
    if args.bucket_name != '':
        bucket = get_bucket_by_name(args.bucket_name)
        if bucket == '':
            print "Creating bucket %s with tag %s." % (args.bucket_name, json.dumps(tag))
            bucket = create_s3_bucket(args.bucket_name, tag)
        else:
            print "REQUESTED BUCKET ALREADY EXISTS"
        print "BUCKET_NAME " + bucket
    else:
        parser.print_help()