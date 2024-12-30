import pytest
import django
from django.conf import settings
from django.core.management import call_command
from django.utils.timezone import now
from rest_framework import status

# Set up Django settings manually if not already set
# Set up Django settings manually if not already set
if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.admin',
            'django.contrib.contenttypes',
            'rest_framework',  # Required for DRF serializers
            'file_app',  # Your custom app
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',  # Use an in-memory database for tests
            }
        },
        SECRET_KEY='dummy-secret-key-for-testing',  # Dummy secret key for testing
        AUTH_USER_MODEL='file_app.User',  # Custom user model
        ROOT_URLCONF='file_app.urls',  # Set to your actual project's URL configuration
    )

# Initialize Django
django.setup()

# Apply migrations to set up the test database schema
call_command('migrate')

from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from file_app.models import File, FileShareToken, FilePermission
from file_app.serializers import FileSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from io import BytesIO
import pyotp
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

User = get_user_model()

# Helper functions for encryption/decryption
def encrypt_test_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data, encryptor.tag

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def create_user():
    def _create_user(username, password, role="user"):
        return User.objects.create_user(username=username, password=password, role=role)
    return _create_user

@pytest.fixture
def login_user(api_client, create_user):
    def _login_user(username, password):
        user = create_user(username=username, password=password)
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        return user
    return _login_user

@pytest.fixture
def setup_file(create_user):
    def _setup_file(owner, content=b"Test content"):
        file = File.objects.create(
            owner=owner,
            file=content,
            original_filename="testfile.txt",
            encrypted=True,
            key={"encryption_key": "test-key"},
            iv={"iv_key": "test-iv"},
        )
        return file
    return _setup_file

@pytest.mark.django_db
def test_register_user(api_client):
    """Test user registration with TOTP and QR code generation."""
    data = {
        "username": "testuser",
        "password": "password123",
        "email": "testuser@example.com",
    }
    response = api_client.post("/register/", data)
    assert response.status_code == 200
    assert "totp_secret" in response.data
    assert "qr_code" in response.data

@pytest.mark.django_db
def test_login_with_mfa_step1(api_client, create_user):
    """Test Step 1 of MFA login."""
    user = create_user(username="mfauser", password="password123")
    user.totp_secret = pyotp.random_base32()
    user.save()

    response = api_client.post("/login/", {"step": "1", "username": "mfauser", "password": "password123"})
    assert response.status_code == 200
    assert response.data["message"] == "Credentials verified, proceed to MFA"

@pytest.mark.django_db
def test_login_with_mfa_step2(api_client, create_user):
    """Test Step 2 of MFA login."""
    user = create_user(username="mfauser", password="password123")
    user.totp_secret = pyotp.random_base32()
    user.save()

    totp = pyotp.TOTP(user.totp_secret)
    valid_code = totp.now()

    response = api_client.post("/login/", {"step": "2", "username": "mfauser", "totp": valid_code})
    assert response.status_code == 200
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

