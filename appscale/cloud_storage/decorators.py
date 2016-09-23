import functools

from boto.s3.connection import OrdinaryCallingFormat
from boto.s3.connection import S3Connection
from flask import current_app
from flask import request
from .constants import HTTP_BAD_REQUEST
from .constants import HTTP_NOT_IMPLEMENTED
from .constants import HTTP_UNAUTHORIZED
from .utils import camel_to_snake
from .utils import error
from .utils import get_user
from .utils import s3_connection_cache
from .utils import TokenNotFound
from .utils import TokenExpired


def assert_required(*required):
    """ A decorator that ensures required parameters are specified. It passes
    them as keyword arguments. """
    def wrapper(function):
        @functools.wraps(function)
        def wrapped_function(*args, **kwargs):
            undefined = [param for param in required
                         if request.args.get(param) is None]
            if undefined:
                return error('Required parameter(s): {}'.format(undefined),
                             HTTP_BAD_REQUEST)
            # Convert the parameter key to snake case and pass it in.
            kwargs.update({camel_to_snake(param): request.args.get(param)
                           for param in required})
            return function(*args, **kwargs)
        return wrapped_function
    return wrapper


def assert_unsupported(*unsupported):
    """ A decorator that ensures no unsupported parameters are defined. """
    def wrapper(function):
        @functools.wraps(function)
        def wrapped_function(*args, **kwargs):
            defined = [param for param in unsupported
                       if request.args.get(param) is not None]
            if defined:
                return error('{} not supported'.format(defined),
                             HTTP_NOT_IMPLEMENTED)
            return function(*args, **kwargs)
        return wrapped_function
    return wrapper


def authenticate(function):
    """ A decorator that authenticates a request and provides a connection. """
    @functools.wraps(function)
    def decorated_function(*args, **kwargs):
        try:
            _, token = request.headers['Authorization'].split()
        except KeyError:
            token = request.args.get('key')
            if token is None:
                return error('Login required.', HTTP_UNAUTHORIZED)

        try:
            user = get_user(token)
        except (TokenNotFound, TokenExpired) as token_error:
            return error(str(token_error), HTTP_UNAUTHORIZED)

        if user not in s3_connection_cache:
            valid_users = current_app.config['USERS']
            if user not in valid_users:
                return error('Invalid token: user not configured.')

            s3_connection_cache[user] = S3Connection(
                aws_access_key_id=valid_users[user]['aws_access_key'],
                aws_secret_access_key=valid_users[user]['aws_secret_key'],
                is_secure=current_app.config['S3_USE_SSL'],
                host=current_app.config['S3_HOST'],
                port=current_app.config['S3_PORT'],
                calling_format=OrdinaryCallingFormat()
            )

        kwargs['conn'] = s3_connection_cache[user]

        return function(*args, **kwargs)
    return decorated_function
