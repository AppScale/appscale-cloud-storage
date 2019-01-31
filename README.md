# AppScale Cloud Storage

A server that implements the
[Google Cloud Storage API](https://cloud.google.com/storage/docs/json_api/). At
this time, it is a wrapper that translates GCS JSON API calls to S3 calls.

# How to set up

1. Set up a PostgreSQL server to use for storing bucket metadata and session
   state.
2. Set up an S3-compatible server to use for storing objects.
3. In `settings.cfg`, specify `S3_ADMIN_CREDS`, `S3_HOST`, `S3_PORT`,
   `POSTGRES_DB`, and define at least one user entry. Use the private key
   defined in a JSON service credentials file to generate the certificate file.
4. Install AppScale Cloud Storage with `python3 setup.py install`. Using a
   virtualenv is recommended.
5. Run `appscale-prime-cloud-storage` to generate the required Postgres tables.
6. Define the following environment variables:
   `export FLASK_APP=appscale.cloud_storage` and
   `export APPSCALE_CLOUD_STORAGE_SETTINGS=/path/to/settings.cfg`.
7. Start the server with `flask run`.

# Using the server

You can use Google's
[client libraries](https://developers.google.com/api-client-library/) or the
[Cloud SDK](https://cloud.google.com/sdk/) to interact with the server. For
authentication, create or use existing JSON service account credentials with
`auth_uri` and `token_uri` pointing to the AppScale Cloud Storage server.

## Python gcloud example

```
# Imports
from gcloud import storage
from oauth2client.service_account import ServiceAccountCredentials

# Configuration
storage.connection.Connection.API_BASE_URL = 'http://[server-address]:[port]'
SCOPES = ['https://www.googleapis.com/auth/devstorage.read_write']
SERVICE_CREDS = '/path/to/service/creds.json'

# Construct the client.
credentials = ServiceAccountCredentials.from_json_keyfile_name(
    SERVICE_CREDS, scopes=scopes)
client = storage.Client(credentials=credentials)
```

# Known Differences

* Due to a limitation in the S3 API, the minimum size for non-terminal chunks
  when performing uploads is 5MB instead of 256KB. In Python, for example, you
  can account for this by defining `chunk_size=5 << 20` when creating
  `storage.blob.Blob` objects.
