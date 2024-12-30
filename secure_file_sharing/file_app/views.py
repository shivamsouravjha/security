import pyotp  # Required for TOTP generation and verification
import qrcode  # Required for generating QR codes
from io import BytesIO  # Used for handling QR code data
from django.db.models import Q  # Used for filtering in queries
from rest_framework.views import APIView  # Base class for API views
from rest_framework.response import Response  # Standardized API responses
from rest_framework.permissions import IsAuthenticated, AllowAny  # Permissions for API views
from rest_framework_simplejwt.tokens import RefreshToken  # JWT token management
from rest_framework import generics, status  # Generic API views and HTTP status codes
from django.contrib.auth import get_user_model  # Dynamically retrieve the user model
from django.shortcuts import get_object_or_404  # Handle objects that may not exist
from django.http import JsonResponse  # Return JSON responses for views
from django.utils.timezone import now, timedelta  # Handle timezone-aware datetimes
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie  # CSRF handling
from rest_framework.decorators import api_view, permission_classes  # For functional views
from itsdangerous import URLSafeTimedSerializer  # Generate and validate secure tokens
from datetime import datetime, timedelta  # Used for handling naive datetimes
from rest_framework.exceptions import PermissionDenied  # Raise permission errors
from .models import File, FileShareToken, FilePermission  # Your custom models
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .serializers import (  # Your serializers for API endpoints
    CustomTokenObtainPairSerializer, 
    UserSerializer, 
    FileSerializer
)
import base64
import os
from django.utils.decorators import method_decorator
from cryptography.hazmat.backends import default_backend

User = get_user_model()

class AccessFileView(APIView):
    """
    Validates the token and provides metadata for accessing a shared file.
    """
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            token_entry = FileShareToken.objects.get(token=token)

            if token_entry.is_expired():
                return Response({"detail": "This link has expired."}, status=status.HTTP_410_GONE)

            token_entry.used = True
            token_entry.save()

            file_instance = token_entry.file

            requesting_user = request.user
            role = "owner" if file_instance.owner == requesting_user else token_entry.permission

            # Decode server-side encryption metadata
            try:
                server_key = base64.b64decode(file_instance.server_key)
                server_iv = base64.b64decode(file_instance.server_iv)
                server_tag = base64.b64decode(file_instance.server_tag)
            except Exception as e:
                return Response(
                    {"detail": f"Failed to decode server encryption metadata: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Decrypt the file using server-side encryption metadata
            try:
                decrypted_data = decrypt_file(file_instance.file, server_key, server_iv, server_tag)
            except Exception as e:
                return Response(
                    {"detail": f"Failed to decrypt the file: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Encode the partially decrypted file content in Base64
            encoded_decrypted_data = base64.b64encode(decrypted_data).decode('utf-8')

            # Prepare the response with partially decrypted data and metadata
            response = {
                "partially_decrypted_file": encoded_decrypted_data,  # Partially decrypted and Base64-encoded
                "client_key": file_instance.key,                    # Client-side key for final decryption
                "client_iv": file_instance.iv,                      # Client-side IV for final decryption
                "original_filename": file_instance.original_filename,
                "role": role,                     # Role or permission from the token
            }

            return Response(response, status=status.HTTP_200_OK)

        except FileShareToken.DoesNotExist:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_404_NOT_FOUND)
class GenerateTokenView(APIView):
    """
    Generates a shareable token for a file with expiration and user-specific permissions.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, file_id):
        # Retrieve the file and validate ownership
        file = get_object_or_404(File, id=file_id)
        if file.owner != request.user:
            return Response({"detail": "You do not have permission to share this file."}, status=status.HTTP_403_FORBIDDEN)

        # Extract required fields from the request
        expires_in = int(request.data.get('expires_in', 3600))  # Default to 1 hour
        permission = request.data.get("permission", "view")  # Default permission is 'view'
        user_id = request.data.get("user_id")
        shared_user = get_object_or_404(User, id=user_id)

        FilePermission.objects.update_or_create(
            file=file,
            user=shared_user,
            defaults={"permission": permission},
        )

        # Create a token entry for the shared file
        token_entry = FileShareToken.objects.create(
            file=file,
            shared_with=shared_user,
            permission=permission,
            expires_at=now() + timedelta(seconds=expires_in),
        )

        # Respond with the token and its expiration timestamp
        return Response(
            {"token": str(token_entry.token), "expires_at": token_entry.expires_at.isoformat()},
            status=status.HTTP_201_CREATED,
        )

class ListUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Return a list of all users with limited information.
        """
        search_query = request.query_params.get('search', '')  # Get the search query from URL params
        if search_query:
            # Filter users by username containing the search query (case-insensitive)
            users = User.objects.filter(Q(username__icontains=search_query)).values('id', 'username')
        else:
            # Return all users if no search query is provided
            users = User.objects.values('id', 'username')

        return Response(users, status=status.HTTP_200_OK)

@ensure_csrf_cookie
def set_csrf_cookie(request):
    csrf_token = request.META.get("CSRF_COOKIE", "")
    return JsonResponse({"csrfToken": csrf_token})


class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(role="guest")
            # Generate and save TOTP secret
            user.totp_secret = pyotp.random_base32()  # Generate a random TOTP secret
            user.save()

            # Generate QR Code for TOTP setup
            totp = pyotp.TOTP(user.totp_secret)
            otp_auth_url = totp.provisioning_uri(name=user.username, issuer_name="SecureFileApp")
            qr = qrcode.make(otp_auth_url)

            buffer = BytesIO()
            qr.save(buffer)
            buffer.seek(0)
            qr_code_hex = buffer.getvalue().hex()

            return Response({
                "message": "User registered successfully.",
                "totp_secret": user.totp_secret,
                "qr_code": qr_code_hex  # Return the QR code as a hex string
            })
        return Response(serializer.errors, status=400)

class LogoutView(APIView):
    """
    Logs the user out by clearing authentication cookies.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({"message": "Logout successful"}, status=200)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

class UserManagementView(APIView):
    """
    Manages user-related actions such as retrieving user info and role.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handles GET requests for retrieving user info or their role.
        If 'role' is present in query parameters, it fetches the user's role.
        Otherwise, it returns user info.
        """
        if 'role' in request.query_params:
            return Response({"role": request.user.role}, status=200)

        # Default to returning user info
        return Response({"username": request.user.username, "role": request.user.role})

class RefreshTokenView(APIView):
    """
    Refreshes the access token using the refresh token from cookies.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({"error": "No refresh token found"}, status=401)

        try:
            refresh = RefreshToken(refresh_token)
            new_access = refresh.access_token
            access_exp = datetime.now() + timedelta(minutes=5)  # Set token expiration

            response = Response({"message": "Access token refreshed"}, status=200)
            response.set_cookie(
                key='access_token',
                value=str(new_access),
                httponly=True,
                secure=True,
                samesite='Strict',
                expires=access_exp
            )
            return response
        except Exception:
            return Response({"error": "Invalid refresh token"}, status=401)

@method_decorator(csrf_exempt, name='dispatch')
class LoginWithMFA(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        step = request.data.get('step')
        username = request.data.get('username')

        if step == '1':
            # Step 1: Validate username and password
            password = request.data.get('password')
            user = User.objects.filter(username=username).first()

            if user and user.check_password(password):
                print(f"TOTP Secret for user {username}: {user.totp_secret}")
                if not user.totp_secret:
                    return Response({"error": "MFA is not enabled", "redirect": "/enable-mfa"}, status=403)
                return Response({"message": "Credentials verified, proceed to MFA", "username": username})

            return Response({"error": "Invalid credentials"}, status=401)

        elif step == '2':
            # Step 2: Validate TOTP
            totp_code = request.data.get('totp')
            user = User.objects.filter(username=username).first()
            print(user)
            if not user:
                return Response({"error": "Invalid credentials"}, status=401)

            if not user.totp_secret:
                return Response({"error": "MFA is not enabled for this account."}, status=403)

            if user and user.totp_secret:  # Ensure TOTP secret exists
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(totp_code):
                    refresh = RefreshToken.for_user(user)
                    print("refredassasadasddsh")
                    refresh["role"] = user.role  # Add the role to the token payload
                    refresh["id"] = user.id
                    access_token = refresh.access_token
                    access_token["role"] = user.role
                    access_token["id"]   = user.id

                    refresh_token_exp = datetime.now() + timedelta(days=7)    # Example: 7-day expiration
                    access_token_exp = datetime.now() + timedelta(minutes=5)  # Example: 5-minute expiration
                    print("refresh_token_exp",refresh_token_exp)
                    response = Response({"message": "Login successful"}, status=status.HTTP_200_OK)
                    response.set_cookie(
                        key='refresh_token',
                        value=str(refresh),
                        httponly=True,
                        secure=True,
                        samesite='Strict',
                        expires=refresh_token_exp
                    )
                    response.set_cookie(
                        key='access_token',
                        value=str(refresh.access_token),
                        httponly=True,       # <--- Cannot be accessed by JavaScript
                        secure=True,         # <--- Only over HTTPS
                        samesite='Strict',   # or 'Lax', helps mitigate CSRF
                        expires=access_token_exp
                    )
                    print("CSRF Token in Response Header:", str(refresh),str(refresh.access_token))
                    return response
                return Response({"error": "Invalid MFA code"}, status=403)

        return Response({"error": "Invalid request"}, status=400)

def generate_aes_key():
    """Generate a secure AES-256 key."""
    return os.urandom(32)  # 256-bit key

def encrypt_data(data, key, iv):
    """Encrypt data using AES-GCM."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data, encryptor.tag

def decrypt_file(encrypted_data, key, iv, tag):
    """
    Decrypt the encrypted file content using AES-256 GCM mode.
    :param encrypted_data: Encrypted file content (bytes).
    :param key: AES-256 encryption key (32 bytes).
    :param iv: Initialization vector (bytes).
    :param tag: Authentication tag (bytes).
    :return: Decrypted file content (bytes).
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


class FileUploadView(generics.CreateAPIView):
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        if self.request.user.role == "guest":
            raise PermissionDenied("Users with the 'guest' role are not allowed to upload files.")
        
        uploaded_file = self.request.FILES['file']
        client_key = self.request.data.get('key')  # Client-side key
        client_iv = self.request.data.get('iv')    # Client-side IV
        file_content = uploaded_file.read()

        server_key = os.urandom(32)  # AES-256 key
        server_iv = os.urandom(12)  # AES-GCM IV
        doubly_encrypted_data, server_tag = encrypt_data(file_content, server_key, server_iv)

        encoded_server_key = base64.b64encode(server_key).decode('utf-8')
        encoded_server_iv = base64.b64encode(server_iv).decode('utf-8')
        encoded_server_tag = base64.b64encode(server_tag).decode('utf-8')
        # Validate that all metadata is generated
        if not encoded_server_key or not encoded_server_iv or not encoded_server_tag:
            raise ValueError("Server-side encryption metadata is missing.")
        serializer.save(
            owner=self.request.user,
            original_filename=uploaded_file.name,
            file=doubly_encrypted_data,  # Doubly encrypted file content
            key=client_key,  # Store client-side key
            iv=client_iv,# Store client-side IV
            server_key=encoded_server_key,  # Store server-side key
            server_iv=encoded_server_iv,    # Store server-side IV
            server_tag=encoded_server_tag,  # Store server-side tag
        )


class FileListView(generics.ListAPIView):
    serializer_class = FileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        print(File.objects.filter(owner=self.request.user),"File.objects.filter(owner=self.request.user)")
        return File.objects.filter(owner=self.request.user)

    def list(self, request, *args, **kwargs):
        """
        Override the list method to customize the response format.
        """
        queryset = self.get_queryset()
        response_data = [
            {
                "id": file.id,
                "key": file.key,
                "iv": file.iv,
                "original_filename": file.original_filename,
                "owner": file.owner.username if file.owner else "Unknown",
                "uuid": file.uuid,
            }
            for file in queryset
        ]
        return Response(response_data)

class ManageUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print(request.user.role,"role")
        if request.user.role != 'admin':
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def delete(self, request, user_id):
        if request.user.role != 'admin':
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({"message": "User deleted successfully"})
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, user_id):
        print("user_id",user_id)
        if request.user.role != 'admin':  # Only admin can update roles
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        print("user_id",user_id)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        new_role = request.data.get('role')
        if new_role not in ['guest', 'user', 'admin']:
            return Response({"error": "Invalid role. Must be 'guest', 'user', or 'admin'."}, status=status.HTTP_400_BAD_REQUEST)

        user.role = new_role
        user.save()
        return Response({"message": f"User role updated to {new_role}."})

# Admin: Manage Files
class ManageFilesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        files = File.objects.all()
        response_data = [
            {
                "id": file.id,
                "key": file.key,
                "iv": file.iv,
                "original_filename": file.original_filename,
                "owner": file.owner.username if file.owner else "Unknown",
                "uuid": file.uuid
            }
            for file in files
        ]

        return Response(response_data)

    def delete(self, request, file_id):
        print("CSRF Token in Request Header:", request.headers.get("X-CSRFToken"))
        if request.user.role != 'admin':
            return Response({"detail": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
        try:
            file = File.objects.get(id=file_id)
            file.delete()
            return Response({"message": "File deleted successfully"})
        except File.DoesNotExist:
            return Response({"detail": "File not found"}, status=status.HTTP_404_NOT_FOUND)

class SharedWithYouView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        shared_files = FilePermission.objects.filter(user=request.user).select_related('file')
        response_data = [
            {
                "id": permission.file.uuid,
                "name": permission.file.original_filename,
                "owner": permission.file.owner.username,
                "permission": permission.permission,
            }
            for permission in shared_files
        ]
        return Response(response_data)
class DownloadFileView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated
    def get(self, request, uuid):
        file_instance = get_object_or_404(File, uuid=uuid)
        if file_instance.owner == request.user:
            has_permission = True  # Owners always have access
        else:
            permission = FilePermission.objects.filter(
                file=file_instance, user=request.user, permission__in=['view', 'download'],
            ).first()
        if file_instance.owner == request.user:
            role = "owner"
        elif permission:
            has_permission = True
            role = permission.permission
        else:
            has_permission = False
            role = None

        if not has_permission:
            return Response({"detail": "You do not have permission to access this file."}, status=status.HTTP_403_FORBIDDEN)
        server_key = base64.b64decode(file_instance.server_key)
        server_iv = base64.b64decode(file_instance.server_iv)
        server_tag = base64.b64decode(file_instance.server_tag)
        decrypted_data = decrypt_file(file_instance.file, server_key, server_iv, server_tag)

        encoded_decrypted_data = base64.b64encode(decrypted_data).decode('utf-8')

        response = {
            "partially_decrypted_file": encoded_decrypted_data,  # Server-side decryption completed
            "client_key": file_instance.key,            # Send client-side key for final decryption
            "client_iv": file_instance.iv,              # Send client-side IV for final decryption
            "original_filename": file_instance.original_filename,
            "role": role
        }

        return Response(response, status=status.HTTP_200_OK)

class GenerateMFASecretView(APIView):
    """
    Generates a new TOTP secret for the user and returns a QR code.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({"error": "Username and password are required."}, status=400)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # Verify password
        if not user.check_password(password):
            return Response({"error": "Invalid password."}, status=403)

        # Check if MFA is already enabled
        if user.totp_secret:
            return Response({"error": "MFA is already enabled."}, status=400)

        # Generate a new TOTP secret
        totp_secret = pyotp.random_base32()
        user.totp_secret = totp_secret
        user.save()

        # Generate a QR code for the TOTP secret
        totp = pyotp.TOTP(totp_secret)
        otp_auth_url = totp.provisioning_uri(name=user.username, issuer_name="SecureFileApp")
        qr = qrcode.make(otp_auth_url)

        buffer = BytesIO()
        qr.save(buffer)
        buffer.seek(0)
        qr_code_hex = buffer.getvalue().hex()

        return Response({
            "message": "TOTP secret generated successfully.",
            "totp_secret": totp_secret,
            "qr_code": qr_code_hex
        })
class EnableMFAView(APIView):
    """
    Enables MFA for the user if they verify the provided TOTP.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        totp_secret = request.data.get('totp_secret')
        totp_code = request.data.get('totp_code')

        if not username or not password or not totp_secret or not totp_code:
            return Response({"error": "All fields are required."}, status=400)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # Verify password
        if not user.check_password(password):
            return Response({"error": "Invalid password."}, status=403)

        # Verify the TOTP code
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code):
            return Response({"error": "Invalid TOTP code."}, status=400)

        # Enable MFA
        user.totp_secret = totp_secret
        user.save()

        return Response({"message": "MFA enabled successfully."})

class VerifyMFAView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        totp_code = request.data.get('totp_code')

        if not username or not totp_code:
            return Response({"error": "Username and TOTP code are required."}, status=400)

        # Fetch the user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # Verify the TOTP code
        totp_secret = user.totp_secret  # Assuming TOTP secret is stored in Profile
        totp = pyotp.TOTP(totp_secret)

        if totp.verify(totp_code):
            user.mfa_enabled = True  # Enable MFA after successful verification
            user.save()
            return Response({"success": True, "message": "MFA verified successfully."})
        else:
            return Response({"success": False, "error": "Invalid TOTP code."}, status=400)
