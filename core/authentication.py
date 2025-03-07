from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get the token from the cookie instead of Authorization header
        token = request.COOKIES.get('access_token')
        
        if not token:
            return None
        
        # Validate CSRF token for unsafe methods
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            self.enforce_csrf(request)
            
        # Use the existing JWT authentication logic
        validated_token = self.get_validated_token(token)
        user = self.get_user(validated_token)
        
        return (user, validated_token)
    
    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for cookie-based auth
        """
        check = CSRFCheck()
        # populates request.META['CSRF_COOKIE']
        check.process_request(request)
        
        csrf_token = request.META.get('CSRF_COOKIE')
        if csrf_token is None:
            raise exceptions.PermissionDenied('CSRF token not found')
            
        # Get the CSRF token from the request header
        request_csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
        
        if not request_csrf_token:
            raise exceptions.PermissionDenied('CSRF token missing')
            
        if not csrf_token == request_csrf_token:
            raise exceptions.PermissionDenied('CSRF token mismatch')