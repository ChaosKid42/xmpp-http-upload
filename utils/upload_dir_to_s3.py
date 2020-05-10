#!/usr/bin/env python
import boto3
import os

from mimetypes import guess_type
from os.path import join

ENDPOINT_URL='http://localhost:9000'
BUCKETNAME='xhu'

#s3 = boto3.resource('s3', endpoint_url=ENDPOINT_URL)
s3 = boto3.resource('s3')

bucket = s3.Bucket(BUCKETNAME)

ROOTDIR = '/var/www/xhu/upload/'

for root, dirs, files in os.walk(ROOTDIR):
  for name in files:
    filepath = join(root, name)
    rel = relpath(filepath, ROOTDIR)
    content_type = guess_type(filepath)[0]
    print(rel, content_type)
    with open(filepath, 'rb') as data:
      if content_type:
        bucket.put_object(Key=rel, Body=data, ContentType=content_type)
      else:
        bucket.put_object(Key=rel, Body=data)
