#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import re
import utils
import boto3
import consul
import subprocess
import sys
from boto3 import client
from utils import DMPConfig
from boto3.session import Session

def check_if_valid_bucket_name(name):
    BUCKET_RE = re.compile(r'^(?![-.])(?!.*[.-]{2})[a-zA-Z0-9.-]{3,63}(?<![.-])$')
    return BUCKET_RE.match(name)


def create_bucket(awskeyid, awssecretkey, bucket_name):
    try:
        session = boto3.Session(awskeyid, awssecretkey)
        s3 = session.resource('s3')
        bucket = s3.create_bucket(Bucket=bucket_name)
        print("Bucket Name: %s created" % bucket.name)
    except NameError:
        sys.exit(1)


def create_user_and_keys(awskeyid, awssecretkey, bucket_name, iam_username, user_policy):
    try:
        session = boto3.Session(awskeyid, awssecretkey)
        iam = session.resource('iam')
        user = iam.create_user(UserName=iam_username)
    except NameError:
        sys.exit(1)
    print("User Name: %s created" % user.name)

    # Create AccessKey/SecretKey pair for User

    accesskeypair = user.create_access_key_pair()
    print("Access Key: %s" % accesskeypair.id)
    print("Access Secret: %s" % accesskeypair.secret)

    iam = session.resource('iam')
    iam.create_policy(PolicyName=('DATASCI-S3-RO-%s' % bucket_name), PolicyDocument=json.dumps(user_policy))
    iam = session.client('iam')
    iam.put_user_policy(PolicyDocument=json.dumps(user_policy), PolicyName=('DATASCI-S3-RO-%s' % bucket_name),
                            UserName=iam_username)

    print("Policy RO created for : {username}".format(username=iam_username))



def delete_user_keys_policy(awskeyid, awssecretkey, iam_username, bucket_name):
        session = boto3.Session(awskeyid, awssecretkey)

        iam = session.client('iam')
        response = iam.list_user_policies(UserName=iam_username)
        for policy_name in response['PolicyNames']:
            print("deleting inline policy for user: {}: {}".format(iam_username, policy_name))

        iam.delete_user_policy(UserName=iam_username, PolicyName=policy_name)
        response = iam.list_access_keys(UserName=iam_username)
        for key_id in [metadata['AccessKeyId'] for metadata in response['AccessKeyMetadata']]:
            print("deleting access key for user {}: {}".format(iam_username, key_id))

        iam.delete_access_key(UserName=iam_username, AccessKeyId=key_id)
        client = session.client('iam')
        response = client.delete_policy(PolicyArn='arn:aws:iam::988965462563:policy/DATASCI-S3-RO-%s' % bucket_name)
        #print(response)

        client = session.client('iam')
        response = client.delete_user(UserName=iam_username)
        print("deleting user: {}".format(iam_username))



def delete_bucket(awskeyid, awssecretkey, bucket_name):
    try:
        session = boto3.Session(awskeyid, awssecretkey)
        client = session.client('s3')
        response = client.delete_bucket(Bucket=bucket_name)
        print('%s bucket deleted successfully' % bucket_name)
    except NameError:
        sys.exit(1)

def list_s3_buckets(awskeyid, awssecretkey):
    try:
        session = boto3.Session(awskeyid, awssecretkey)
        #s3 = boto3.resource('s3')
        s3 = session.resource('s3')
        for bucket in s3.buckets.all():
           print(bucket.name)
    except NameError:
        sys.exit(1)

#def list_s3_buckets(aws_access_key_id, aws_secret_access_key):
#        ACCESS_KEY='AKIAJ3SSZ36C3VPM2BPQ'
#        SECRET_KEY='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'

#        session = Session(aws_access_key_id=ACCESS_KEY,
#                          aws_secret_access_key=SECRET_KEY)
#        s3 = boto3.resource('s3')
#        for bucket in s3.buckets.all():
#           print(bucket.name)


def main():

    bucket_name = sys.argv[1]
    iam_username = sys.argv[2]
    action = sys.argv[3]
    dmpConfig = DMPConfig()
    AWS_ACCESS_KEY_ID = dmpConfig.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = dmpConfig.get("AWS_SECRET_ACCESS_KEY")
    aws_access_key_iD = AWS_ACCESS_KEY_ID
    aws_secret_access_keY = AWS_SECRET_ACCESS_KEY
    awskeyid = aws_access_key_iD.decode('utf-8')
    awssecretkey = aws_secret_access_keY.decode('utf-8')
    user_policy = {"Version": "2012-10-17",
                   "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                                  "Resource": ["arn:aws:s3:::%s/*" % bucket_name,
                                               "arn:aws:s3:::%s" % bucket_name]}]}



    if action == '-C':
        create_bucket(awskeyid, awssecretkey, bucket_name)
        create_user_and_keys(awskeyid, awssecretkey, bucket_name, iam_username, user_policy)
    elif action == '-cu':
        create_user_and_keys(awskeyid, awssecretkey, bucket_name, iam_username, user_policy)
    elif action == '-cb':
        create_bucket(awskeyid, awssecretkey, bucket_name)
    elif action == '-D':
        delete_user_keys_policy(awskeyid, awssecretkey, iam_username, bucket_name)
        delete_bucket(awskeyid, awssecretkey, bucket_name)
    elif action == '-du':
        delete_user_keys_policy(awskeyid, awssecretkey, iam_username, bucket_name)
    elif action == '-db':
        delete_bucket(awskeyid, awssecretkey, bucket_name)
    elif action == '-L':
        list_s3_buckets(awskeyid, awssecretkey)
    else:

        print("there is no action in the command ,excepted -C \ -cb \ -cu for create or -D /-db /-du for delete")


if __name__ == "__main__":
    main()

