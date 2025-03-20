from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from datetime import timedelta

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get the token from the cookie instead of Authorization header
        token = request.COOKIES.get('access_token')
        
        if not token:
            if settings.DEBUG:
                print("No access token found in cookies")
            return None
            
        try:
            # Validate CSRF token for unsafe methods
            if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                self.enforce_csrf(request)
                
            # Use the existing JWT authentication logic
            validated_token = self.get_validated_token(token)
            user = self.get_user(validated_token)
            
            return (user, validated_token)
        except Exception as e:
            if settings.DEBUG:
                print(f"Authentication error: {str(e)}")
                print(f"Request headers: {request.headers}")
                print(f"Request cookies: {request.COOKIES}")
            return None
    
    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for cookie-based auth
        """
        # Skip CSRF check for test client
        if hasattr(request, '_dont_enforce_csrf_checks'):
            return

        # Optional development bypass (use with caution)
        if settings.DEBUG and getattr(settings, 'CSRF_DEVELOPMENT_BYPASS', False):
            if settings.DEBUG:
                print("CSRF validation bypassed in development mode")
            return
        
        try:
            # Get the CSRF token from the request header
            request_csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            
            if not request_csrf_token:
                if settings.DEBUG:
                    print("CSRF token missing in request header")
                raise exceptions.PermissionDenied('CSRF token missing')
                
            # Get the CSRF token from the cookie
            csrf_token = request.COOKIES.get('csrftoken')
            
            if not csrf_token:
                if settings.DEBUG:
                    print("CSRF cookie not found")
                raise exceptions.PermissionDenied('CSRF cookie not found')
                
            if request_csrf_token != csrf_token:
                if settings.DEBUG:
                    print(f"CSRF token mismatch: {request_csrf_token} != {csrf_token}")
                raise exceptions.PermissionDenied('CSRF token mismatch')
                
            if settings.DEBUG:
                print("CSRF validation successful")
                
        except Exception as e:
            if settings.DEBUG:
                print(f"CSRF validation error: {str(e)}")
                print(f"Request headers: {request.headers}")
                print(f"Request cookies: {request.COOKIES}")
            raise