import base64
import binascii
import datetime
import dateutil.parser
import gzip
import json
import math
import random
import re

from boto.exception import S3ResponseError
from boto.s3.key import Key

from flask import current_app
from flask import request
from flask import Response
from flask import url_for
from io import BytesIO
from .constants import EPOCH
from .constants import HTTP_BAD_REQUEST
from .constants import HTTP_NO_CONTENT
from .constants import HTTP_NOT_FOUND
from .constants import HTTP_NOT_IMPLEMENTED
from .constants import HTTP_OK
from .constants import HTTP_PARTIAL_CONTENT
from .constants import HTTP_RESUME_INCOMPLETE
from .decorators import assert_required
from .decorators import assert_unsupported
from .decorators import authenticate
from .utils import calculate_md5
from .utils import completed_bytes
from .utils import delete_object_metadata
from .utils import error
from .utils import get_completed_ranges
from .utils import get_object_metadata
from .utils import get_request_from_state
from .utils import get_upload_state
from .utils import set_object_metadata
from .utils import upsert_upload_state
from .utils import UploadNotFound
from .utils import UploadStates


def object_info(key, last_modified=None):
    """ Generates a dictionary representing a GCS object.

    Args:
        key: A boto Key object.
        last_modified: A datetime object specifying when the object was
            last modified.
    Returns:
        A JSON-safe dictionary representing the object.
    """
    if last_modified is None:
        last_modified = dateutil.parser.parse(key.last_modified)

    # TODO: Check if using last modified is appropriate for generation.
    last_mod_usec = int((last_modified - EPOCH).total_seconds() * 1000000)
    key_id = '/'.join([key.bucket.name, key.name, str(last_mod_usec)])
    object_url = url_for('get_object', bucket_name=key.bucket.name,
                         object_name=key.name)

    obj = {
        'kind': 'storage#object',
        'id': key_id,
        'selfLink': request.url_root[:-1] + object_url,
        'name': key.name,
        'bucket': key.bucket.name,
        'generation': str(last_mod_usec),
        'etag': key.etag[1:-1],
        'mediaLink': request.url_root[:-1] + object_url + '?alt=media',
        'size': str(key.size)
    }

    # Multipart uploads do not have MD5 metadata by default.
    if key.md5 is not None:
        md5 = binascii.unhexlify(key.md5)
        obj['md5Hash'] = base64.b64encode(md5).decode()
    elif '-' not in key.etag:
        md5 = bytearray.fromhex(key.etag[1:-1])
        obj['md5Hash'] = base64.b64encode(md5).decode()
    else:
        metadata = get_object_metadata(key)
        obj.update(metadata)

    current_app.logger.debug('obj: {}'.format(obj))
    return obj


def read_object(key, chunk_size):
    """ A generator that fetches object data.

    Args:
        key: A boto Key object.
        chunk_size: An integer specifying the chunk size to use when fetching.
    """
    while True:
        data = key.resp.read(chunk_size)
        if not data:
            key.close()
            break
        yield data


@authenticate
def list_objects(bucket_name, conn):
    """ Retrieves a list of objects.

    Args:
        bucket_name: A string specifying a bucket name.
        conn: An S3Connection instance.
    Returns:
        A JSON string representing an object.
    """
    # TODO: Get bucket ACL.
    response = {'kind': 'storage#objects'}
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return error('Not Found', HTTP_NOT_FOUND)
        raise s3_error

    keys = tuple(bucket.list())
    if not keys:
        return Response(json.dumps(response), mimetype='application/json')

    response['items'] = [object_info(key) for key in keys]
    return Response(json.dumps(response), mimetype='application/json')


@authenticate
def delete_object(bucket_name, object_name, conn):
    """ Deletes an object and its metadata.

    Args:
        bucket_name: A string specifying a bucket name.
        object_name: A string specifying an object name.
        conn: An S3Connection instance.
    """
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return error('Not Found', HTTP_NOT_FOUND)
        raise s3_error

    # TODO: Do the following lookup and delete under a lock.
    key = bucket.get_key(object_name)
    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    delete_object_metadata(key)
    key.delete()
    return '', HTTP_NO_CONTENT


@authenticate
@assert_unsupported('generation', 'ifGenerationMatch', 'ifGenerationNotMatch',
                    'ifMetagenerationMatch', 'ifMetagenerationNotMatch')
def get_object(bucket_name, object_name, conn):
    """ Retrieves an object or its metadata.

    Args:
        bucket_name: A string specifying a bucket_name.
        object_name: A string specifying an object name.
        conn: An S3Connection instance.
    Returns:
        A JSON string representing an object.
    """
    projection = request.args.get('projection') or 'noAcl'
    if projection != 'noAcl':
        return error('projection: {} not supported.'.format(projection),
                     HTTP_NOT_IMPLEMENTED)

    alt = request.args.get('alt', default='json')
    if alt not in ['json', 'media']:
        return error('alt: {} not supported.'.format(projection),
                     HTTP_BAD_REQUEST)

    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError as s3_error:
        if s3_error.status == HTTP_NOT_FOUND:
            return error('Not Found', HTTP_NOT_FOUND)
        raise s3_error
    key = bucket.get_key(object_name)

    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    if alt == 'media':
        boto_headers = None
        content_length = key.size
        response_range = None
        status_code = HTTP_OK
        if 'Range' in request.headers:
            boto_headers = {'Range': request.headers['Range']}
            requested_range = request.headers['Range'].split('=')[-1]
            start_byte, end_byte = (int(val) for val
                                    in requested_range.split('-'))
            requested_length = end_byte - start_byte + 1
            remaining_length = key.size - start_byte
            content_length = min(remaining_length, requested_length)
            status_code = HTTP_PARTIAL_CONTENT
            response_end_byte = min(end_byte, key.size - 1)
            response_range = 'bytes {}-{}/{}'.format(
                start_byte, response_end_byte, key.size)

        key.open_read(headers=boto_headers)
        response = Response(
            response=read_object(key, current_app.config['READ_SIZE']),
            status=status_code
        )
        response.headers['Content-Length'] = content_length
        if response_range is not None:
            response.headers['Content-Range'] = response_range
        response.headers['Content-Type'] = key.content_type
        return response

    obj = object_info(key)
    return Response(json.dumps(obj), mimetype='application/json')


@authenticate
@assert_required('uploadType')
def insert_object(bucket_name, upload_type, conn):
    """ Stores an object or starts a resumable upload.

    Args:
        bucket_name: A string specifying a bucket name.
        object_name: A string specifying an object name.
        conn: An S3Connection instance.
    Returns:
        A JSON string representing an object.
    """
    bucket = conn.get_bucket(bucket_name)
    object_name = request.args.get('name', default=None)
    upload_id = request.args.get('upload_id', default=None)

    if upload_type == 'media':
        if object_name is None:
            return error('Object name is required.', HTTP_BAD_REQUEST)

        # Decompress content if necessary.
        if 'Content-Encoding' in request.headers:
            if request.headers['Content-Encoding'] == 'gzip':
                content = gzip.decompress(request.data)
            else:
                return error('Unrecognized Content-Encoding.',
                             HTTP_NOT_IMPLEMENTED)
        else:
            content = request.data

        key = Key(bucket, object_name)
        key.set_contents_from_string(content)
        obj = object_info(
            key, last_modified=datetime.datetime.now(datetime.timezone.utc))
        return Response(json.dumps(obj), mimetype='application/json')
    if upload_type == 'resumable' and upload_id is None:
        if object_name is None:
            return error('Object name is required.', HTTP_BAD_REQUEST)

        new_upload_id = ''.join(
            random.choice(current_app.config['RESUMABLE_ID_CHARS'])
            for _ in range(current_app.config['RESUMABLE_ID_LENGTH']))
        current_app.logger.debug('new upload_id: {}, object: {}'.format(
            new_upload_id, object_name))

        state = {'object': object_name, 'status': UploadStates.NEW}
        upsert_upload_state(new_upload_id, state)

        upload_url = url_for('insert_object', bucket_name=bucket_name)
        redirect = request.url_root[:-1] + upload_url + \
                   '?uploadType=resumable&upload_id={}'.format(new_upload_id)
        response = Response('')
        response.headers['Location'] = redirect
        return response
    if upload_type == 'multipart':
        try:
            match = re.match(r"^multipart/related; boundary='(.*)'$",
                             request.headers['Content-Type'])
            boundary = match.group(1)
        except (KeyError, AttributeError):
            return error('Invalid Content-Type.', HTTP_BAD_REQUEST)
        parts = request.data.split(b'--' + boundary.encode())
        metadata = json.loads(parts[1].decode().splitlines()[-1])
        file_data = parts[2].split(b'\n\n', maxsplit=1)[-1]
        if file_data.endswith(b'\n'):
            file_data = file_data[:-1]

        current_app.logger.debug('metadata: {}'.format(metadata))
        object_name = metadata['name']
        key = Key(bucket, object_name)
        if 'contentType' in metadata:
            key.set_metadata('Content-Type', metadata['contentType'])
        key.set_contents_from_string(file_data)
        obj = object_info(
            key, last_modified=datetime.datetime.now(datetime.timezone.utc))
        return Response(json.dumps(obj), mimetype='application/json')

    return error('Invalid uploadType.', HTTP_BAD_REQUEST)


@authenticate
@assert_required('upload_id')
def resumable_insert(bucket_name, upload_id, conn):
    """ Stores all or part of an object.

    Args:
        bucket_name: A string specifying a bucket name.
        object_name: A string specifying an object name.
        conn: An S3Connection instance.
    Returns:
        A JSON string representing an object.
    """
    try:
        upload_state = get_upload_state(upload_id)
    except UploadNotFound as state_error:
        return error(str(state_error), HTTP_BAD_REQUEST)

    if 'Content-Encoding' in request.headers:
        return error('Content-Encoding not permitted on resumable uploads.',
                     HTTP_BAD_REQUEST)

    object_name = upload_state['object']
    request_length = int(request.headers['Content-Length'])
    unit, content_range = request.headers['Content-Range'].split()
    if unit != 'bytes':
        return error('Content-Range must be specified in bytes.',
                     HTTP_BAD_REQUEST)

    current_portion, total_length = content_range.split('/')
    bucket = conn.get_bucket(bucket_name)
    if current_portion == '*':
        if upload_state['status'] == UploadStates.COMPLETE:
            obj = object_info(bucket.get_key(object_name))
            return Response(json.dumps(obj), mimetype='application/json')
        upload_request = get_request_from_state(
            upload_id, upload_state, bucket)
        response = Response('', status=HTTP_RESUME_INCOMPLETE)
        range_strings = ['{}-{}'.format(start, end) for start, end
                         in get_completed_ranges(upload_request)]
        if range_strings:
            response.headers['Range'] = 'bytes=' + ','.join(range_strings)
        return response

    try:
        total_length = int(total_length)
        start, end = [int(value) for value in current_portion.split('-')]
    except ValueError:
        return error('Invalid Content-Range.', HTTP_BAD_REQUEST)

    chunk_size = current_app.config['UPLOAD_CHUNK_SIZE']
    if (end - start + 1) % chunk_size != 0 and end != (total_length - 1):
        return error('Non-termninal chunk sizes must be multiples '
                     'of {}'.format(chunk_size), HTTP_BAD_REQUEST)

    request_chunks = math.ceil(request_length / chunk_size)
    chunk_start = start / chunk_size + 1
    if chunk_start != int(chunk_start):
        return error(
            'Content-Range start must be a multiple of {}'.format(chunk_size))
    chunk_start = int(chunk_start)

    upload_request = get_request_from_state(upload_id, upload_state, bucket)

    for chunk_num in range(chunk_start, chunk_start + request_chunks):
        offset = chunk_size * (chunk_num - 1)
        current_chunk_size = min(chunk_size, total_length - offset)
        # Boto requires a file object when uploading a part, but Flask's
        # request.stream cannot seek.
        chunk = BytesIO(request.stream.read(chunk_size))
        upload_request.upload_part_from_file(chunk, part_num=chunk_num,
                                             size=current_chunk_size)

    completed_ranges = get_completed_ranges(upload_request)
    if completed_bytes(completed_ranges) == total_length:
        # Ideally, the MD5 would be calculated before the request is finalized,
        # but there doesn't seem to be a way to fetch part data beforehand.
        upload_request.complete_upload()
        key = bucket.get_key(object_name)
        md5 = calculate_md5(key)

        # TODO: Clean up old upload state info after a week.
        new_state = {'status': UploadStates.COMPLETE, 'object': object_name}
        upsert_upload_state(upload_id, new_state)

        key.md5 = binascii.hexlify(md5)
        set_object_metadata(key, {'md5Hash': base64.b64encode(md5).decode()})
        return Response(json.dumps(object_info(key)),
                        mimetype='application/json')

    response = Response('', status=HTTP_RESUME_INCOMPLETE)
    range_strings = ['{}-{}'.format(start, end)
                     for start, end in completed_ranges]
    response.headers['Range'] = 'bytes=' + ','.join(range_strings)
    return response
