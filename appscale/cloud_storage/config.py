import string

# The number of characters in an access token.
ACCESS_TOKEN_LENGTH = 77

# A reserved Riak KV bucket used for storing bucket metadata.
METADATA_BUCKET = 'appscale-cloud-storage-bucket-metadata'

# A reserved Riak KV bucket used for storing authentication tokens.
TOKEN_BUCKET = 'appscale-cloud-storage-auth-tokens'

# A reserved Riak KV bucket used for storing upload session state.
UPLOAD_SESSION_BUCKET = 'appscale-cloud-storage-upload-ids'

# The location of a Riak KV installation.
RIAK_KV_HOST = 'localhost'

# The port for Riak KV's HTTP interface.
RIAK_KV_HTTP_PORT = 8098

# The S3 credentials to use for performing administrative S3 operations.
S3_ADMIN_CREDS = {'access_key': '', 'secret_key': ''}

# The S3 endpoint to use as a storage backend. Don't specify S3 itself. Use
# a service with a compatible API such as Riak S2.
S3_HOST = 'localhost'
S3_PORT = 8080
S3_USE_SSL = False

# The host and port that AppScale Cloud Storage should serve on.
SERVER_NAME = 'localhost:5000'

# The number of seconds a token should be good for.
TOKEN_EXPIRATION = 3600

# The accounts that are authorized to use AppScale Cloud Storage. The keys
# correspond to client_email in your JSON service credentials file. The values
# are dictionaries specifying the path to the certificate associated with the
# service credentials and existing AWS-style credentials to use with that
# account.
USERS = {}

# The chunk size to use when fetching object data from S3.
READ_SIZE = 1 << 20

# The length of upload ID string.
RESUMABLE_ID_LENGTH = 14

# The characters used when generating upload ID strings.
RESUMABLE_ID_CHARS = string.ascii_uppercase + string.digits + '_'

# The chunk size to use when uploading data to S3. S3 requires a minimum of
# 5MB for non-terminal chunks, but GCS allows 256KB chunks.
UPLOAD_CHUNK_SIZE = 5 << 20
