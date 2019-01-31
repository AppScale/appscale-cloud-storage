""" Primes the metadata backend. """

from appscale.cloud_storage.utils import pg_connection


def prime():
    """ Populates the metadata backend with the required tables. """
    with pg_connection.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS buckets (
            project text,
            bucket text,
            PRIMARY KEY (project, bucket)
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token text PRIMARY KEY,
            user_id text,
            expiration timestamp
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id text PRIMARY KEY,
            state text
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS object_metadata (
            bucket text,
            object text,
            metadata text,
            PRIMARY KEY (bucket, object)
        );
        """)

    pg_connection.commit()
