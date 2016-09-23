import datetime
import dateutil.parser
import json
import re

from flask import Response
from riak.riak_object import RiakObject
from .constants import HTTP_ERROR

# A cache used to store valid access tokens.
active_tokens = {}

# A cache used to store active S3 connections.
s3_connection_cache = {}

# These global variables are defined when the app starts.
metadata_bucket = None  # The Riak KV bucket that stores bucket metadata.
riak_connection = None  # A Riak KV client connection.
token_bucket = None  # The Riak KV bucket that stores auth tokens.
upload_session_bucket = None  # The Riak KV bucket that stores session data.


class TokenExpired(Exception):
    """ Indicates that a given authentication token has expired. """
    pass


class TokenNotFound(Exception):
    """ Indicates that a given authentication token does not exist. """
    pass


class UploadNotFound(Exception):
    """ Indicates that a given Upload ID does not exist. """
    pass


class UploadStates(object):
    """ Possible statuses for resumable uploads. """
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    COMPLETE = 'complete'


def camel_to_snake(name):
    """ Convert a string from camelCase to snake_case. """
    return re.sub('([a-z])([A-Z])', r'\1_\2', name).lower()


def error(message, code=HTTP_ERROR):
    """ A convenience function for formatting error messages. """
    response = json.dumps({'error': {'message': message, 'code': code}})
    return Response(response, mimetype='application/json', status=code)


def index_bucket(bucket_name, project):
    """ Associates a bucket with a project. """
    bucket = riak_connection.bucket(metadata_bucket)
    obj = RiakObject(riak_connection, bucket, bucket_name)
    obj.add_index('project', project)
    obj.store()


def query_buckets(project):
    """ Fetches a set of bucket names in a given project. """
    bucket = riak_connection.bucket(metadata_bucket)
    return set(bucket.get_index(project).results)


def set_token(token, user_id, expiration):
    """ Defines a valid token.

    Args:
        token: A string containing the token ID.
        user_id: A string containing the user ID.
        aws_creds: A dictionary containing AWS credentials.
        expiration: A datetime object specifying the token expiration.
    """
    bucket = riak_connection.bucket(token_bucket)
    # TODO: Clean up expired tokens.
    bucket.new(token, {'user': user_id, 'expiration': expiration.isoformat()})
    active_tokens[token] = {'user': user_id, 'expiration': expiration}


def get_user(token):
    """ Retrieves a user dictionary from a given token.

    Args:
        token: A string containing the token ID.
    Raises:
        TokenNotFound: Indicates that the token can't be found.
        TokenExpired: Indicates that the token has expired.
    """
    # Check if the token is already cached.
    if token in active_tokens:
        if datetime.datetime.now() <= active_tokens[token]['expiration']:
            return active_tokens[token]['user']
        raise TokenExpired('Token expired.')

    # Try to fetch the token from Riak KV.
    bucket = riak_connection.bucket(token_bucket)
    token = bucket.get(token)
    if not token.exists:
        raise TokenNotFound('Token not found.')

    expiration = dateutil.parser.parse(token.data['expiration'])
    if datetime.datetime.now() > expiration:
        raise TokenExpired('Token expired.')

    active_tokens[token] = {'user': token.data['user'],
                            'expiration': expiration}
    return active_tokens[token]['user']
