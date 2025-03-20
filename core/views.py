from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.middleware import csrf

from rest_framework import status, viewsets, permissions, generics
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import MagicCode
from .serializers import (
    UserSerializer, 
    UserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    MagicCodeRequestSerializer,
    MagicCodeVerifySerializer,
    CheckUserSerializer,
)

User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token view that uses our enhanced token serializer."""
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Get tokens from the response data
            access_token = response.data.get('access')
            refresh_token = response.data.get('refresh')
            
            # Get token lifetimes from settings
            access_token_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
            refresh_token_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            
            # Set the access token in an HTTP-only cookie
            response.set_cookie(
                key='access_token',
                value=access_token,
                max_age=int(access_token_lifetime.total_seconds()),
                httponly=True,
                samesite=settings.SESSION_COOKIE_SAMESITE,
                secure=settings.SESSION_COOKIE_SECURE,
                path='/'
            )
            
            # Set the refresh token in an HTTP-only cookie
            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                max_age=int(refresh_token_lifetime.total_seconds()),
                httponly=True,
                samesite=settings.SESSION_COOKIE_SAMESITE,
                secure=settings.SESSION_COOKIE_SECURE,
                path='/'
            )
            
            # Set CSRF token in a non-HTTP-only cookie (needed for CSRF protection)
            csrf_token = csrf.get_token(request)
            response.set_cookie(
                key='csrftoken',
                value=csrf_token,
                max_age=60 * 60 * 24 * 7,  # 7 days
                httponly=False,  # CSRF token must be accessible to JavaScript
                samesite=settings.CSRF_COOKIE_SAMESITE,
                secure=settings.CSRF_COOKIE_SECURE,
                path='/'
            )
            
            # Keep user data in response but remove tokens from JSON body
            # since they're now in cookies
            if 'access' in response.data:
                del response.data['access']
            if 'refresh' in response.data:
                del response.data['refresh']
                
        return response

class UserRegistrationView(generics.CreateAPIView):
    """View for user registration."""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

class UserView(generics.RetrieveUpdateAPIView):
    """View for retrieving and updating user details."""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user

@api_view(['POST'])
@permission_classes([AllowAny])
def check_user_exists(request):
    """API endpoint to check if a user exists and get their role."""
    serializer = CheckUserSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            return Response({
                "email": email,
                "exists": True,
                "role": user.role
            })
        except User.DoesNotExist:
            return Response({
                "email": email,
                "exists": False
            })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
@api_view(['POST'])
@permission_classes([AllowAny])
def request_magic_code(request):
    """API endpoint to request a magic code with CAPTCHA verification."""
    serializer = MagicCodeRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        
        # Generate magic code (5-digit number)
        magic_code = MagicCode.generate_code(user)

        # if in development mode, console log the magic code
        if settings.DEBUG:
            print(f"Magic code for {email}: {magic_code.code}")
        
        # Send email with magic code
        send_mail(
            'Your Login Code',
            f'Your 5-digit magic code is: {magic_code.code}',
            'noreply@example.com',
            [email],
            fail_silently=False,
        )
        
        return Response({
            "message": "Magic code sent successfully",
            "email": email
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_magic_code(request):
    """API endpoint to verify a magic code and return tokens."""
    serializer = MagicCodeVerifySerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        magic_code = serializer.validated_data['magic_code']
        
        # Mark the code as used
        magic_code.is_used = True
        magic_code.save()
        
        # Verify the user's email if not already verified
        if not user.is_verified:
            user.verify_email()
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Create the response
        response = Response({
            'user': UserSerializer(user).data
        })
        
        # Get token lifetimes from settings
        access_token_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
        refresh_token_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
        
        # Set the access token in an HTTP-only cookie
        response.set_cookie(
            key='access_token',
            value=access_token,
            max_age=int(access_token_lifetime.total_seconds()),
            httponly=True,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            secure=settings.SESSION_COOKIE_SECURE,
            path='/'
        )
        
        # Set the refresh token in an HTTP-only cookie
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            max_age=int(refresh_token_lifetime.total_seconds()),
            httponly=True,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            secure=settings.SESSION_COOKIE_SECURE,
            path='/'
        )
        
        # Set CSRF token in a non-HTTP-only cookie
        csrf_token = csrf.get_token(request)
        response.set_cookie(
            key='csrftoken',
            value=csrf_token,
            max_age=60 * 60 * 24 * 7,  # 7 days
            httponly=False,  # CSRF token must be accessible to JavaScript
            samesite=settings.CSRF_COOKIE_SAMESITE,
            secure=settings.CSRF_COOKIE_SECURE,
            path='/'
        )
        
        return response
        
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_email(request):
    """API endpoint to manually verify a user's email."""
    user = request.user
    
    # Only verify if not already verified
    if not user.is_verified:
        user.verify_email()
        return Response({
            "message": "Email verified successfully",
            "user": UserSerializer(user).data
        })
    else:
        return Response({
            "message": "Email already verified",
            "user": UserSerializer(user).data
        })

@api_view(['POST'])
@permission_classes([AllowAny])
def admin_login(request):
    """API endpoint for admin/moderator login with magic code verification only.
    
    This endpoint is now deprecated as all users (including admins) should use
    the standard magic code verification flow.
    """
    # Redirect to the standard magic code verification flow
    return Response({
        "message": "This endpoint is deprecated. Please use the standard magic code verification flow.",
        "redirect": "auth/magic-code/verify/"
    }, status=status.HTTP_308_PERMANENT_REDIRECT)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_user(request):
    """API endpoint to delete a user's own account."""
    user = request.user
    
    # Only allow users to delete their own accounts
    # Admins and moderators should use the admin interface for user management
    if user.role == 'USER':
        try:
            # Get tokens before deleting the user
            refresh_token = request.COOKIES.get('refresh_token')
            
            # Perform the deletion
            user.delete()
            
            # Create response
            response = Response({"message": "Account deleted successfully"}, status=status.HTTP_200_OK)
            
            # Clear all auth-related cookies with proper domain and path
            response.delete_cookie('access_token', path='/')
            response.delete_cookie('refresh_token', path='/')
            response.delete_cookie('csrftoken', path='/')
            
            # Blacklist the token if it exists
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except Exception as e:
                    if settings.DEBUG:
                        print(f"Error blacklisting token: {e}")
            
            return response
        except Exception as e:
            if settings.DEBUG:
                print(f"Error deleting account: {e}")
            return Response(
                {"message": "Error deleting account"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(
            {"message": "Admin and moderator accounts cannot be deleted through this endpoint"}, 
            status=status.HTTP_403_FORBIDDEN
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Invalidate the user's token and clear cookies on logout."""
    try:
        # Get tokens
        refresh_token = request.COOKIES.get('refresh_token')
        
        # Create response first
        response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        
        # Clear all auth-related cookies
        response.delete_cookie('access_token', path='/')
        response.delete_cookie('refresh_token', path='/')
        response.delete_cookie('csrftoken', path='/')
        
        # Blacklist the token if it exists
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                # Log the error but don't fail the request
                print(f"Error blacklisting token during logout: {e}")
        
        return response
    except Exception as e:
        if settings.DEBUG:
            print(f"Logout error: {e}")
        return Response(
            {"message": "Error during logout"}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_count(request):
    """API endpoint to get the total number of users."""
    if request.user.role not in ['ADMIN', 'MODERATOR']:
        return Response(
            {"message": "You are not authorized to access this endpoint"}, 
            status=status.HTTP_403_FORBIDDEN
        )
    regular_user_count = User.objects.filter(role='USER').count()
    return Response({"regular_user_count": regular_user_count}, status=status.HTTP_200_OK)

class CustomTokenRefreshView(APIView):
    """Custom token refresh view that works with HTTP-only cookies."""
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        # Get refresh token from cookie
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return Response(
                {"error": "Refresh token not found"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Create a refresh token instance and get a new access token
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            # Get token lifetime from settings
            access_token_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
            
            # Prepare the response
            response = Response({'detail': 'Token refreshed successfully'})
            
            # Set the new access token as an HTTP-only cookie
            response.set_cookie(
                key='access_token',
                value=access_token,
                max_age=int(access_token_lifetime.total_seconds()),
                httponly=True,
                samesite=settings.SESSION_COOKIE_SAMESITE,
                secure=settings.SESSION_COOKIE_SECURE,
                path='/'
            )
            
            # If rotation is enabled, update the refresh token too
            if settings.SIMPLE_JWT.get('ROTATE_REFRESH_TOKENS', False):
                # Get the new refresh token
                new_refresh_token = str(refresh)
                refresh_token_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
                
                # Set the new refresh token as an HTTP-only cookie
                response.set_cookie(
                    key='refresh_token',
                    value=new_refresh_token,
                    max_age=int(refresh_token_lifetime.total_seconds()),
                    httponly=True,
                    samesite=settings.SESSION_COOKIE_SAMESITE,
                    secure=settings.SESSION_COOKIE_SECURE,
                    path='/'
                )
            
            return response
            
        except TokenError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )
