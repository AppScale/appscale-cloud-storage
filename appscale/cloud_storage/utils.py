import datetime
import hashlib
import itertools
import json
import re

from boto.s3.multipart import MultiPartUpload
from flask import Response
from .constants import HTTP_ERROR

# A cache used to store valid access tokens.
active_tokens = {}

# A cache used to store active S3 connections.
s3_connection_cache = {}

# A psycopg2 connection.
pg_connection = None

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
    """ Converts a string from camelCase to snake_case.

    Args:
        name: A string in camelCase.
    Returns:
        A string in snake_case.
    """
    return re.sub('([a-z])([A-Z])', r'\1_\2', name).lower()


def error(message, code=HTTP_ERROR):
    """ A convenience function for formatting error messages.

    Args:
        message: A string containing the error message.
        code: An integer containing an HTTP status code.
    Returns:
        A JSON string specifying the error.
    """
    response = json.dumps({'error': {'message': message, 'code': code}})
    return Response(response, mimetype='application/json', status=code)


def index_bucket(bucket_name, project):
    """ Associates a bucket with a project.

    Args:
        bucket_name: A string containing the bucket name.
        project: A string containing the project ID.
    """
    with pg_connection.cursor() as cur:
        cur.execute('INSERT INTO buckets (project, bucket) VALUES (%s, %s)',
                    (project, bucket_name))

    pg_connection.commit()


def query_buckets(project):
    """ Fetches a set of bucket names in a given project.

    Args:
        project: A string containing the project ID.
    Returns:
        A set of strings containing bucket names.
    """
    with pg_connection.cursor() as cur:
        cur.execute('SELECT bucket FROM buckets WHERE project = %s',
                    (project,))
        buckets = {result[0] for result in cur.fetchall()}

    pg_connection.rollback()
    return buckets


def set_token(token, user_id, expiration):
    """ Defines a valid token.

    Args:
        token: A string containing the token ID.
        user_id: A string containing the user ID.
        expiration: A datetime object specifying the token expiration.
    """
    # TODO: Clean up expired tokens.
    with pg_connection.cursor() as cur:
        cur.execute('INSERT INTO tokens (token, user_id, expiration) '
                    'VALUES (%s, %s, %s)',
                    (token, user_id, expiration))

    pg_connection.commit()


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

    # Try to fetch the token from Postgres.
    with pg_connection.cursor() as cur:
        cur.execute('SELECT user_id, expiration FROM tokens WHERE token = %s',
                    (token,))
        result = cur.fetchone()

    pg_connection.rollback()

    if result is None:
        raise TokenNotFound('Token not found.')

    user, expiration = result
    if datetime.datetime.now() > expiration:
        raise TokenExpired('Token expired.')

    active_tokens[token] = {'user': user, 'expiration': expiration}
    return active_tokens[token]['user']


def upsert_upload_state(upload_id, state):
    """ Stores or updates state for a given upload ID.

    Args:
        upload_id: A string specifying the upload ID.
        state: A dictionary containing the upload state.
    """
    with pg_connection.cursor() as cur:
        cur.execute('SELECT state FROM uploads WHERE id = %s', (upload_id,))
        result = cur.fetchone()
        if result is None:
            new_state = state
        else:
            new_state = json.loads(result[0])
            new_state.update(state)

        cur.execute('INSERT INTO uploads (id, state) VALUES (%s, %s) '
                    'ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state',
                    (upload_id, json.dumps(new_state)))

    pg_connection.commit()


def get_upload_state(upload_id):
    """ Fetches state for a given upload ID.

    Args:
        upload_id: A string specifying the upload ID.
    Returns:
        A dictionary containing the upload state.
    """
    with pg_connection.cursor() as cur:
        cur.execute('SELECT state FROM uploads WHERE id = %s', (upload_id,))
        result = cur.fetchone()

    pg_connection.rollback()

    if result is None:
        raise UploadNotFound('Invalid upload_id.')

    return json.loads(result[0])


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
    """ Fetches the total number of bytes stored for an upload.

    Args:
        completed_ranges: A tuple of tuples specifying the start and end bytes
            of completed parts.
    Returns:
        An integer specifying the total number of completed bytes.
    """
    return sum([end - start + 1 for start, end in completed_ranges])


def get_request_from_state(upload_id, upload_state, bucket):
    """ Fetches or creates a MultiPartUpload object for an upload ID.

    Args:
        upload_id: A string specifying the upload ID.
        upload_state: A dictionary containing upload state.
        bucket: A boto Bucket object.
    """
    if upload_state['status'] == UploadStates.NEW:
        upload_request = bucket.initiate_multipart_upload(
            upload_state['object'])
        new_state = {'status': UploadStates.IN_PROGRESS,
                     'object': upload_state['object'],
                     'id': upload_request.id}
        upsert_upload_state(upload_id, new_state)
    else:
        upload_request = MultiPartUpload(bucket=bucket)
        upload_request.id = upload_state['id']
        upload_request.key_name = upload_state['object']
    return upload_request


def calculate_md5(key):
    """ Calculates an MD5 digest for an object.

    Args:
        key: A boto Key object.
    Returns:
        A bytes object containing the MD5 digest.
    """
    md5_hash = hashlib.md5()
    while True:
        object_data = key.read(size=config['READ_SIZE'])
        if len(object_data) == 0:
            break
        md5_hash.update(object_data)
    return md5_hash.digest()


def set_object_metadata(key, data):
    """ Updates object metadata.

    Args:
        key: A boto Key object.
        data: A dictionary containing object metadata.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connection.cursor() as cur:
        cur.execute('INSERT INTO object_metadata (bucket, object, metadata) '
                    'VALUES (%s, %s, %s) '
                    'ON CONFLICT (bucket, object) '
                    'DO UPDATE SET metadata = EXCLUDED.metadata',
                    (bucket_name, object_name, json.dumps(data)))

    pg_connection.commit()


def get_object_metadata(key):
    """ Fetches object metadata.

    Args:
        key: A boto Key object.
    Returns:
        A dictionary containing object metadata.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connection.cursor() as cur:
        cur.execute('SELECT metadata FROM object_metadata '
                    'WHERE bucket = %s AND object = %s',
                    (bucket_name, object_name))
        result = cur.fetchone()

    pg_connection.rollback()

    if result is None:
        return {}

    return json.loads(result[0])


def delete_object_metadata(key):
    """ Deletes an object's metadata.

    Args:
        key: A boto Key object.
    """
    bucket_name = key.bucket.name
    object_name = key.name
    with pg_connection.cursor() as cur:
        cur.execute('DELETE FROM object_metadata '
                    'WHERE bucket = %s AND object = %s',
                    (bucket_name, object_name))

    pg_connection.commit()
