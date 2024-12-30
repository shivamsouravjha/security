from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import File
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom serializer for adding user role to the JWT token payload.
    """
    def validate(self, attrs):
        # Validate the default token fields (username and password)
        data = super().validate(attrs)
        
        # Add user role to the token payload
        data['role'] = self.user.role
        return data


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model, including fields for role and password.
    """
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'role')
        extra_kwargs = {
            'role': {'read_only': True},  # Exclude from input validation
            'password': {'write_only': True},  # Ensure password is write-only
        }


    def create(self, validated_data):
        """
        Create a new user instance with the provided validated data.
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data.get('role', 'user')  # Default role is 'user'
        )
        return user


class FileSerializer(serializers.ModelSerializer):
    """
    Serializer for the File model, supporting optional encryption key and IV fields.
    """
    key = serializers.JSONField(required=False)  # Encryption key (optional)
    iv = serializers.JSONField(required=False)   # Initialization vector (optional)
    server_key = serializers.CharField(required=False) # Server-side encryption key
    server_iv = serializers.CharField(required=False)  # Server-side IV
    server_tag = serializers.CharField(required=False) # Server-side authentication tag
    class Meta:
        model = File
        fields = [
            'id', 'file', 'uuid', 'key', 'iv', 'server_key', 'server_iv', 'server_tag',
            'original_filename', 'encrypted','owner',
        ]
        read_only_fields = ['server_key', 'server_iv', 'server_tag', 'encrypted', 'uuid', 'owner']
    def create(self, validated_data):
        """
        Create a new file instance with optional shared_with handling.
        """
        file = File.objects.create(**validated_data)  # Create the file instance
        file.encrypted = True
        file.save()
        return file

    def get_owner(self, obj):
        """
        Retrieve the owner's username.
        """
        return obj.owner.username if obj.owner else None
