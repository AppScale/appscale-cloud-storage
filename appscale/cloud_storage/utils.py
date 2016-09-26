import datetime
import dateutil.parser
import itertools
import json
import re

from boto.s3.multipart import MultiPartUpload
from flask import Response
from riak.riak_object import RiakObject
from .constants import HTTP_ERROR

# A cache used to store valid access tokens.
active_tokens = {}

# A cache used to store active S3 connections.
s3_connection_cache = {}

# A Riak KV client connection.
riak_connection = None

# This configuration is defined when the app starts.
config = None


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
    bucket = riak_connection.bucket(config['METADATA_BUCKET'])
    obj = RiakObject(riak_connection, bucket, bucket_name)
    obj.add_index('project', project)
    obj.store()


def query_buckets(project):
    """ Fetches a set of bucket names in a given project. """
    bucket = riak_connection.bucket(config['METADATA_BUCKET'])
    return set(bucket.get_index(project).results)


def set_token(token, user_id, expiration):
    """ Defines a valid token.

    Args:
        token: A string containing the token ID.
        user_id: A string containing the user ID.
        aws_creds: A dictionary containing AWS credentials.
        expiration: A datetime object specifying the token expiration.
    """
    bucket = riak_connection.bucket(config['TOKEN_BUCKET'])
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
    bucket = riak_connection.bucket(config['TOKEN_BUCKET'])
    token = bucket.get(token)
    if not token.exists:
        raise TokenNotFound('Token not found.')

    expiration = dateutil.parser.parse(token.data['expiration'])
    if datetime.datetime.now() > expiration:
        raise TokenExpired('Token expired.')

    active_tokens[token] = {'user': token.data['user'],
                            'expiration': expiration}
    return active_tokens[token]['user']


def set_upload_state(upload_id, state):
    """ Stores state for a given upload ID. """
    bucket = riak_connection.bucket(upload_session_bucket)
    bucket.new(upload_id, data=state).store()


def update_upload_state(upload_id, state):
    """ Updates state for a given upload ID. """
    bucket = riak_connection.bucket(config['UPLOAD_SESSION_BUCKET'])
    obj = bucket.get(upload_id)
    obj.data.update(state)
    obj.store()


def get_upload_state(upload_id):
    """ Fetches state for a given upload ID. """
    bucket = riak_connection.bucket(config['UPLOAD_SESSION_BUCKET'])
    state = bucket.get(upload_id)
    if not state.exists:
        raise UploadNotFound('Invalid upload_id.')
    return state.data


def get_completed_ranges(upload_request):
    """ Fetches list of tuples specifying completed ranges for an upload.

    Args:
        upload_request: A MultiPartUpload object.
    Returns:
        A list of tuples specifying completed byte ranges.
    """
    def drift(index_part):
        index, part = index_part
        return index - part.part_number

    completed_ranges = []
    for _, group in itertools.groupby(enumerate(upload_request), drift):
        group = list(group)
        first_part = group[0][1]
        part_size = first_part.size
        start_of_range = (first_part.part_number - 1) * part_size

        last_part = group[-1][1]
        start_of_last_part = (last_part.part_number - 1) * part_size
        end_of_last_part = start_of_last_part + last_part.size - 1

        completed_ranges.append((start_of_range, end_of_last_part))
    return completed_ranges


def completed_bytes(completed_ranges):
    """ Fetches the total number of bytes stored for an upload. """
    return sum([end - start + 1 for start, end in completed_ranges])


def get_request_from_state(upload_id, upload_state, bucket):
    """ Fetches or creates a MultiPartUpload object for an upload ID. """
    if upload_state['status'] == UploadStates.NEW:
        upload_request = bucket.initiate_multipart_upload(
            upload_state['object'])
        new_state = {'status': UploadStates.IN_PROGRESS,
                     'object': upload_state['object'],
                     'id': upload_request.id}
        update_upload_state(upload_id, new_state)
    else:
        upload_request = MultiPartUpload(bucket=bucket)
        upload_request.id = upload_state['id']
        upload_request.key_name = upload_state['object']
    return upload_request
