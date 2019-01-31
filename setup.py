from setuptools import setup

setup(
    name='appscale-cloud-storage',
    version='0.1.0',
    description='A GCS-compatible storage server',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3'
    ],
    keywords='appscale cloud storage gcs',
    packages=['appscale', 'appscale.cloud_storage'],
    install_requires=[
        'boto',
        'flask',
        'oauth2client',
        'psycopg2',
        'python-dateutil'
    ],
    entry_points={'console_scripts': [
        'appscale-prime-cloud-storage=appscale.cloud_storage.prime:prime']
    }
)
