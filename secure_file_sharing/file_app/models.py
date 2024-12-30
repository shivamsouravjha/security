from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid
from django.utils.timezone import now

# Custom User model
class User(AbstractUser):
    """
    Extends the default AbstractUser model to include additional fields for roles,
    email uniqueness, and support for TOTP (Time-based One-Time Password) authentication.
    """
    ROLE_CHOICES = [
        ('admin', 'Admin'),  # Admin role for managing users and files
        ('user', 'User'),    # Regular user with standard permissions
        ('guest', 'Guest'),  # Guest user with limited permissions
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    email = models.EmailField(unique=True)  # Email must be unique for each user
    totp_secret = models.CharField(max_length=100, null=True, blank=True)  # For storing TOTP secrets

    # Override default related_name to avoid clashes with other models
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",  # Avoid name clashes with default user model
        blank=True,
        help_text="The groups this user belongs to.",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permissions",  # Avoid name clashes with default user permissions
        blank=True,
        help_text="Specific permissions for this user.",
    )

# File model for storing and managing uploaded files
class File(models.Model):
    """
    Represents a file uploaded by a user. Supports encryption and sharing with other users.
    """
    owner = models.ForeignKey(User, on_delete=models.CASCADE)  # User who owns the file
    file = models.BinaryField()   # File content stored as binary data
    encrypted = models.BooleanField(default=False)  # Indicates if the file is encrypted
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for file creation
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  # Unique identifier for the file
    original_filename = models.CharField(max_length=255, blank=True, null=True)  # Original filename of the file
    key = models.JSONField(blank=True, null=True)  # Encryption key (stored in JWK format)
    iv = models.JSONField(blank=True, null=True)  # Initialization vector (used in encryption)
    server_key = models.TextField(blank=True, null=True)  # Server-side encryption key (Base64)
    server_iv = models.TextField(blank=True, null=True)   # Server-side IV (Base64)
    server_tag = models.TextField(blank=True, null=True)  # Server-side tag (Base64)

    def save(self, *args, **kwargs):
        """
        Override the save method to set the original filename if not provided.
        """
        if not self.original_filename and self.file:
            self.original_filename = 'file.bin'  # Since BinaryField does not have a name
        super().save(*args, **kwargs)

    def encrypt_file(self, key):
        """
        Encrypt the file content using the provided key.
        Args:
            key (str): Encryption key in string format.
        """
        from cryptography.fernet import Fernet
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(self.file)  # Encrypt the file content
        self.file = encrypted_data  # Update the file content
        self.encrypted = True  # Mark the file as encrypted
        self.save()

    def decrypt_file(self, key):
        """
        Decrypt the file content using the provided key.
        Args:
            key (str): Decryption key in string format.
        """
        from cryptography.fernet import Fernet
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(self.file)  # Decrypt the file content
        self.file = decrypted_data  # Update the file content
        self.save()

# FileShareToken model for managing shareable links
class FileShareToken(models.Model):
    """
    Represents a temporary shareable token for accessing a file. Tokens are time-bound and can
    enforce specific permissions (e.g., view or download).
    """
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)  # Unique token
    file = models.ForeignKey('File', on_delete=models.CASCADE)  # File associated with the token
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # User the file is shared with
    permission = models.CharField(
        max_length=10,
        choices=[('view', 'View'), ('download', 'Download')],
    )  # Permission level for the token
    expires_at = models.DateTimeField()  # Expiry timestamp for the token
    used = models.BooleanField(default=False)  # Indicates if the token has been used
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for token creation

    def is_expired(self):
        """
        Check if the token has expired.
        Returns:
            bool: True if the token is expired, False otherwise.
        """
        return now() > self.expires_at

# FilePermission model for managing user-specific permissions on files
class FilePermission(models.Model):
    """
    Represents a specific permission (e.g., view or download) granted to a user for a file.
    """
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='permissions')  # File for which permission is granted
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_permissions')  # User receiving the permission
    permission = models.CharField(
        max_length=20,
        choices=[('view', 'View'), ('download', 'Download')],
    )  # Permission type

    class Meta:
        unique_together = ('file', 'user')  # Ensure unique permissions per user-file pair
