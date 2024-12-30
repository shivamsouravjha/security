from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError

class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT Authentication class that retrieves the access token from cookies
    instead of the Authorization header.
    """
    
    def authenticate(self, request):
        """
        Authenticate the user by validating the JWT token present in the cookies.

        Args:
            request (HttpRequest): The incoming request object.

        Returns:
            tuple: A tuple containing the authenticated user and the validated token,
                   or None if authentication fails.
        """
        # Retrieve the access token from the cookies
        access_token = request.COOKIES.get('access_token')
        
        if access_token:
            try:
                # Validate the token using SimpleJWT's methods
                validated_token = self.get_validated_token(access_token)
                
                # Retrieve the user associated with the validated token
                return self.get_user(validated_token), validated_token
            except TokenError as e:
                # Handle token validation errors (e.g., expired or invalid token)
                print(f"Access token error: {str(e)}")
        
        # Return None if no token is found or validation fails
        return None
