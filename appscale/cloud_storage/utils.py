import json

from flask import Response
from .constants import HTTP_ERROR

# A cache used to store valid access tokens.
active_tokens = {}

# These global variables are defined when the app starts.
riak_connection = None  # A Riak KV client connection.
token_bucket = None  # The Riak KV bucket that stores auth tokens.


def error(message, code=HTTP_ERROR):
    """ A convenience function for formatting error messages. """
    response = json.dumps({'error': {'message': message, 'code': code}})
    return Response(response, mimetype='application/json', status=code)


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
