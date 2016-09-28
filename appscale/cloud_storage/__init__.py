#!/usr/bin/env python3

from boto.s3.connection import OrdinaryCallingFormat
from boto.s3.connection import S3Connection
from appscale.cloud_storage import buckets
from appscale.cloud_storage import oauth
from appscale.cloud_storage import objects
from appscale.cloud_storage import utils
from flask import Flask
from riak import RiakClient

app = Flask(__name__)
app.config.from_object('appscale.cloud_storage.config')

try:
    app.config.from_envvar('APPSCALE_CLOUD_STORAGE_SETTINGS')
except RuntimeError:
    app.logger.info('No custom settings specified.')


utils.admin_connection = S3Connection(
    aws_access_key_id=app.config['S3_ADMIN_CREDS']['access_key'],
    aws_secret_access_key=app.config['S3_ADMIN_CREDS']['secret_key'],
    is_secure=app.config['S3_USE_SSL'],
    host=app.config['S3_HOST'],
    port=app.config['S3_PORT'],
    calling_format=OrdinaryCallingFormat()
)
utils.riak_connection = RiakClient(nodes=app.config['RIAK_KV_NODES'])
utils.config = app.config


# Buckets
app.add_url_rule('/storage/v1/b',
                 view_func=buckets.list_buckets, methods=['GET'])
app.add_url_rule('/storage/v1/b',
                 view_func=buckets.insert_bucket, methods=['POST'])
app.add_url_rule('/storage/v1/b/<bucket_name>',
                 view_func=buckets.get_bucket, methods=['GET'])
app.add_url_rule('/storage/v1/b/<bucket_name>',
                 view_func=buckets.delete_bucket, methods=['DELETE'])

# Objects
app.add_url_rule('/storage/v1/b/<bucket_name>/o',
                 view_func=objects.list_objects, methods=['GET'])
app.add_url_rule('/storage/v1/b/<bucket_name>/o/<object_name>',
                 view_func=objects.get_object, methods=['GET'])
app.add_url_rule('/storage/v1/b/<bucket_name>/o/<object_name>',
                 view_func=objects.delete_object, methods=['DELETE'])
app.add_url_rule('/upload/storage/v1/b/<bucket_name>/o',
                 view_func=objects.insert_object, methods=['POST'])
app.add_url_rule('/upload/storage/v1/b/<bucket_name>/o',
                 view_func=objects.resumable_insert, methods=['PUT'])

# Access Tokens
app.add_url_rule('/o/oauth2/token',
                 view_func=oauth.get_token, methods=['POST'])
