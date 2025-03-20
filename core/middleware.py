from django.http import JsonResponse
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()

class RoleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Try to get token from cookie first, then fall back to Authorization header
        token = request.COOKIES.get('access_token')
        
        if not token and request.META.get('HTTP_AUTHORIZATION', '').startswith('Bearer '):
            token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            
        if not token:
            return self.get_response(request)

        try:
            # Decode token
            access_token = AccessToken(token)
            # Get user ID from token
            user_id = access_token['user_id']
            # Get user
            user = User.objects.get(id=user_id)
            # Add user role to request
            request.user_role = user.role
        except Exception as e:
            if settings.DEBUG:
                print(f"Role middleware error: {e}")
            pass

        return self.get_response(request)