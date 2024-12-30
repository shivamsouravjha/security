import sys
import os
import django
from django.conf import settings
from django.core.management import call_command

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
    )

# Initialize Django
django.setup()

# Apply migrations to set up the test database schema
call_command('migrate')

# Adjust sys.path for imports
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '/Users/shivamsouravjha/security/secure_file_sharing/file_app'))
sys.path.insert(0, parent_dir)

# Import test-related modules AFTER setting up Django
import pytest
from io import BytesIO
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework_simplejwt.tokens import RefreshToken
from file_app.models import File
from file_app.serializers import CustomTokenObtainPairSerializer, UserSerializer, FileSerializer

# Define the User model for testing
User = get_user_model()

@pytest.mark.django_db
def test_custom_token_obtain_pair_serializer():
    """Test CustomTokenObtainPairSerializer validation and role inclusion."""
    user = User.objects.create_user(
        username="testuser",
        email="testuser@example.com",
        password="password123",
        role="admin",
    )
    serializer = CustomTokenObtainPairSerializer(data={
        "username": "testuser",
        "password": "password123"
    })

    assert serializer.is_valid()
    validated_data = serializer.validated_data
    token = RefreshToken.for_user(user)

    assert validated_data["role"] == "admin"  # Check if role is included


@pytest.mark.django_db
def test_user_serializer_create():
    """Test UserSerializer create method."""
    serializer = UserSerializer(data={
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "password123",
    })

    assert serializer.is_valid()
    user = serializer.save()

    assert user.username == "newuser"
    assert user.email == "newuser@example.com"
    assert user.role == "user"  # Default role
    assert user.check_password("password123")


@pytest.mark.django_db
def test_file_serializer_create():
    """Test FileSerializer create method."""
    user = User.objects.create_user(
        username="fileowner",
        email="fileowner@example.com",
        password="password123",
    )
    file_data = BytesIO(b"Test file content")
    uploaded_file = SimpleUploadedFile("testfile.txt", file_data.getvalue(), content_type="text/plain")

    serializer = FileSerializer(data={
        "file": uploaded_file,
        "original_filename": "testfile.txt",
    })
    assert serializer.is_valid()
    file = serializer.save(owner=user)

    assert file.original_filename == "testfile.txt"
    assert file.encrypted is True
    assert file.owner == user
