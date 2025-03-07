from django.http import JsonResponse
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model

User = get_user_model()

class RoleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for non-authenticated requests
        if not request.META.get('HTTP_AUTHORIZATION', '').startswith('Bearer '):
            return self.get_response(request)

        try:
            # Extract token
            token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
            # Decode token
            access_token = AccessToken(token)
            # Get user ID from token
            user_id = access_token['user_id']
            # Get user
            user = User.objects.get(id=user_id)
            # Add user role to request
            request.user_role = user.role
        except Exception:
            pass

        return self.get_response(request)