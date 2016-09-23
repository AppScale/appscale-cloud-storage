#!/usr/bin/env python3

from appscale.cloud_storage import oauth
from appscale.cloud_storage import utils
from flask import Flask
from riak import RiakClient

app = Flask(__name__)
app.config.from_object('appscale.cloud_storage.config')

try:
    app.config.from_envvar('APPSCALE_CLOUD_STORAGE_SETTINGS')
except RuntimeError:
    app.logger.info('No custom settings specified.')

utils.riak_connection = RiakClient(nodes=app.config['RIAK_KV_NODES'])
utils.token_bucket = app.config['TOKEN_BUCKET']


# Access Tokens
app.add_url_rule('/o/oauth2/token',
                 view_func=oauth.get_token, methods=['POST'])
