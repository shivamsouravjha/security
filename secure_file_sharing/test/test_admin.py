import sys
import os
import django
from django.conf import settings
# Set up Django settings manually if not already set
if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.admin',
            'django.contrib.contenttypes',
            'rest_framework',  # Add any other required apps here
            'file_app',  # Your app that contains the auth module
            # Add any other apps your project needs
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': 'test_db',  # Using an in-memory DB for testing
            }
        },
        SECRET_KEY='dummy-secret-key-for-testing',  # Add a dummy SECRET_KEY for testing
    )
# Initialize Django
django.setup()
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '/Users/shivamsouravjha/security/secure_file_sharing/file_app'))

sys.path.insert(0, parent_dir)

import file_app.admin # checking coverage for file - do not remove

def test_dummy():
    assert True
