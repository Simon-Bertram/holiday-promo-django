from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

from rest_framework import status, viewsets, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import MagicCode
from .serializers import (
    UserSerializer, 
    UserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    MagicCodeRequestSerializer,
    MagicCodeVerifySerializer
)

User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token view that uses our enhanced token serializer."""
    serializer_class = CustomTokenObtainPairSerializer

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
def request_magic_code(request):
    """API endpoint to request a magic code."""
    serializer = MagicCodeRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        
        # Generate magic code
        magic_code = MagicCode.generate_code(user)
        
        # Send email with magic code
        send_mail(
            'Your Login Code',
            f'Your magic code is: {magic_code.code}',
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
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        })
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
