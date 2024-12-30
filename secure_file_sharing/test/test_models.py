import sys
import os
import django
from django.conf import settings
from django.core.management import call_command
import io
from django.core.files.uploadedfile import InMemoryUploadedFile
from cryptography.fernet import Fernet
if os.path.exists("test_db"):
    os.remove("test_db")
# Set up Django settings manually if not already set
if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.admin',
            'django.contrib.contenttypes',
            'rest_framework',  # Add any other required apps here
            'file_app',  # Your app that contains the auth module
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': 'test_db',  # Using an in-memory DB for testing
            }
        },
        SECRET_KEY='dummy-secret-key-for-testing',  # Add a dummy SECRET_KEY for testing
        AUTH_USER_MODEL='file_app.User',  # Custom user model
    )
# Initialize Django
django.setup()
# Apply migrations to create the necessary tables
call_command('migrate')
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '/Users/shivamsouravjha/security/secure_file_sharing/file_app'))
sys.path.insert(0, parent_dir) # Do not modify this
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from file_app.models import File, FileShareToken
import os
@pytest.mark.django_db
def test_create_user():
    """Test creating a user with all fields, including custom ones"""
    user = get_user_model().objects.create_user(
        username='testuser',
        email='testuser@example.com',
        password='password123',
        role='admin',  # custom role
    )
    assert user.username == 'testuser'
    assert user.email == 'testuser@example.com'
    assert user.role == 'admin'
    assert user.check_password('password123')  # Ensure password check works
@pytest.mark.django_db
def test_user_role_default():
    """Test that the default role is 'user'"""
    user = get_user_model().objects.create_user(
        username='guestuser',
        email='guestuser@example.com',
        password='password123',
    )
    assert user.role == 'user'  # default role
# Test generated using Keploy
@pytest.mark.django_db
def test_file_save_does_not_overwrite_original_filename():
    user = get_user_model().objects.create_user(
        username='fileowner',
        email='fileowner2@example.com',
        password='password123',
    )
    file_content = b'Test file content'
    file = File(owner=user, file=file_content, original_filename='custom_name')
    file.save()
    assert file.original_filename == 'custom_name'
# Test generated using Keploy
@pytest.mark.django_db
def test_is_expired_returns_false_when_not_expired():
    """Test that the is_expired method returns False when the token is still valid."""
    user = get_user_model().objects.create_user(
        username='testuser2',
        email='testuser2@example.com',
        password='password123',
    )
    # Create an in-memory file
    file_data = io.BytesIO(b"Test file content")
    file_data.name = 'testfile.txt'
    file_data.seek(0)
    # Create the file instance
    file_content = b"Test file content"
    file = File.objects.create(
        owner=user,
        file=file_content,  # Pass raw bytes directly
        encrypted=False,
        original_filename='testfile.txt',
    )
    # Create a valid token with an expiry time in the future
    valid_token = FileShareToken.objects.create(
        file=file,
        shared_with=user,  # Optional, can be None
        permission='view',
        expires_at=timezone.now() + timezone.timedelta(hours=1),  # Expiry 1 hour in the future
    )
    # Assert that the token is not expired
    assert valid_token.is_expired() is False
# Test generated using Keploy
@pytest.mark.django_db
def test_decrypt_file_with_correct_key():
    """
    Test that decrypt_file correctly decrypts an encrypted file when provided with the correct key.
    """
    from cryptography.fernet import Fernet
    user = get_user_model().objects.create_user(
        username='testuser1',
        email='testuser1@example.com',
        password='password123',
    )
    # Create a File instance with some content
    file_content = b'Test file content.'
    file = File.objects.create(owner=user, file=file_content)
    # Generate a key and encrypt the file
    key = Fernet.generate_key()
    file.encrypt_file(key)
    # Ensure the file is encrypted
    assert file.file != file_content
    # Decrypt the file
    file.decrypt_file(key)
    # Check that the file content is back to the original
    assert file.file == file_content