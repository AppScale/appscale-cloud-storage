import datetime
import json
import random
import string

from flask import current_app
from flask import request
from flask import Response
from oauth2client.crypt import AppIdentityError
from oauth2client.crypt import verify_signed_jwt_with_certs
from .constants import HTTP_BAD_REQUEST
from .constants import HTTP_UNAUTHORIZED
from .utils import error
from .utils import set_token


def get_token():
    """ Creates an authentication token for valid service credentials.

    Returns:
        A JSON string containing a bearer token.
    """
    config = current_app.config
    try:
        jwt = request.form['assertion']
    except KeyError:
        return error('JWT assertion not defined.', HTTP_BAD_REQUEST)

    valid_users = config['USERS']

    public_keys = {}
    for user in valid_users:
        with open(valid_users[user]['certificate']) as certificate:
            public_keys[user] = certificate.read()

    try:
        payload = verify_signed_jwt_with_certs(
            jwt, public_keys, audience=request.url)
    except AppIdentityError:
        return error('Unable to verify assertion.', HTTP_UNAUTHORIZED)

    try:
        user = payload['iss']
    except KeyError:
        return error('User not defined in JWT assertion.', HTTP_BAD_REQUEST)

    if user not in valid_users:
        return error('{} not configured.'.format(user), HTTP_UNAUTHORIZED)

    token = ''.join(random.choice(string.ascii_letters + string.digits + '._-')
                    for _ in range(config['ACCESS_TOKEN_LENGTH']))
    current_app.logger.debug('new token: {}'.format(token))

    expiration = datetime.timedelta(seconds=config['TOKEN_EXPIRATION'])
    set_token(token, user, expiration=datetime.datetime.now() + expiration)

    response = {
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': config['TOKEN_EXPIRATION']
    }
    return Response(json.dumps(response), mimetype='application/json')
