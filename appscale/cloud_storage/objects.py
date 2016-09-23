import base64
import datetime
import dateutil.parser
import gzip
import json
import math
import random

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
from .constants import HTTP_RESUME_INCOMPLETE
from .decorators import assert_required
from .decorators import assert_unsupported
from .decorators import authenticate
from .utils import completed_bytes
from .utils import error
from .utils import get_completed_ranges
from .utils import get_request_from_state
from .utils import get_upload_state
from .utils import set_upload_state
from .utils import update_upload_state
from .utils import UploadNotFound
from .utils import UploadStates


def object_info(key, last_modified=None):
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
        'mediaLink': request.url_root[:-1] + object_url + '?alt=media'
    }

    # Multipart uploads do not have MD5 metadata.
    if '-' not in key.etag:
        md5 = bytearray.fromhex(key.etag[1:-1])
        obj['md5Hash'] = base64.b64encode(md5).decode()

    return obj


def read_object(key, size):
    key.open_read()
    while True:
        response = key.read(size=size)
        if len(response) == 0:
            key.close()
            break
        yield response


@authenticate
def list_objects(bucket_name, conn):
    """ Retrieves a list of objects. """
    # TODO: Get bucket ACL.
    response = {'kind': 'storage#objects'}
    bucket = conn.get_bucket(bucket_name)
    keys = tuple(bucket.list())
    if not keys:
        return json.dumps(response)

    response['items'] = [object_info(key) for key in keys]
    return Response(json.dumps(response), mimetype='application/json')


@authenticate
def delete_object(bucket_name, object_name, conn):
    """ Deletes an object and its metadata. """
    try:
        bucket = conn.get_bucket(bucket_name)
    except S3ResponseError:
        return error('Not Found', HTTP_NOT_FOUND)

    # TODO: Do the following lookup and delete under a lock.
    key = bucket.get_key(object_name)
    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    key.delete()
    return '', HTTP_NO_CONTENT


@authenticate
@assert_unsupported('generation', 'ifGenerationMatch', 'ifGenerationNotMatch',
                    'ifMetagenerationMatch', 'ifMetagenerationNotMatch')
def get_object(bucket_name, object_name, conn):
    """ Retrieves an object or its metadata. """
    projection = request.args.get('projection') or 'noAcl'
    if projection != 'noAcl':
        return error('projection: {} not supported.'.format(projection),
                     HTTP_NOT_IMPLEMENTED)

    alt = request.args.get('alt')
    if alt is not None and alt != 'media':
        return error('alt: {} not supported.'.format(projection),
                     HTTP_BAD_REQUEST)

    bucket = conn.get_bucket(bucket_name)
    key = bucket.get_key(object_name)

    if key is None:
        return error('Not Found', HTTP_NOT_FOUND)

    if alt == 'media':
        return Response(read_object(key, current_app.config['READ_SIZE']))

    obj = object_info(key)
    return Response(json.dumps(obj), mimetype='application/json')


@authenticate
@assert_required('uploadType')
def insert_object(bucket_name, upload_type, conn):
    bucket = conn.get_bucket(bucket_name)

    object_name = None
    object_name = request.args.get('name') or object_name

    upload_id = None
    upload_id = request.args.get('upload_id') or upload_id

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
        set_upload_state(new_upload_id, state)

        upload_url = url_for('insert_object', bucket_name=bucket_name)
        redirect = request.url_root[:-1] + upload_url + \
                   '?uploadType=resumable&upload_id={}'.format(new_upload_id)
        response = Response('')
        response.headers['Location'] = redirect
        return response
    if upload_type == 'multipart':
        return '', HTTP_NOT_IMPLEMENTED

    return error('Invalid uploadType.', HTTP_BAD_REQUEST)


@authenticate
@assert_required('upload_id')
def resumable_insert(bucket_name, upload_id, conn):
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
        upload_request.complete_upload()
        # TODO: Clean up old state info after a week.
        new_state = {'status': UploadStates.COMPLETE, 'object': object_name}
        update_upload_state(upload_id, new_state)
        obj = object_info(bucket.get_key(object_name))
        return Response(json.dumps(obj), mimetype='application/json')

    response = Response('', status=HTTP_RESUME_INCOMPLETE)
    range_strings = ['{}-{}'.format(start, end)
                     for start, end in completed_ranges]
    response.headers['Range'] = 'bytes=' + ','.join(range_strings)
    return response
