# The number of characters in an access token.
ACCESS_TOKEN_LENGTH = 77

# A reserved Riak KV bucket used for storing authentication tokens.
TOKEN_BUCKET = 'appscale-cloud-storage-auth-tokens'

# The location of a Riak KV installation.
RIAK_KV_HOST = 'localhost'

# The port for Riak KV's HTTP interface.
RIAK_KV_HTTP_PORT = 8098

# The number of seconds a token should be good for.
TOKEN_EXPIRATION = 3600

# The accounts that are authorized to use AppScale Cloud Storage. The keys
# correspond to client_email in your JSON service credentials file. The values
# are dictionaries specifying the path to the certificate associated with the
# service credentials and existing AWS-style credentials to use with that
# account.
USERS = {}
