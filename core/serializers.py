from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import requests 
from django.conf import settings

from .models import MagicCode

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the User model."""
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'role', 'is_verified', 'verified_at']
        read_only_fields = ['id', 'verified_at']

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']
        
    def create(self, validated_data):
        # Set username to email address
        validated_data['username'] = validated_data['email']
        # Generate a random password since we won't be using it
        import secrets
        random_password = secrets.token_urlsafe(32)
        validated_data['password'] = random_password
        user = User.objects.create_user(**validated_data)
        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom token serializer that includes user data and role."""
    
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add extra responses here
        data['user'] = UserSerializer(self.user).data
        
        return data

class MagicCodeRequestSerializer(serializers.Serializer):
    """Serializer for requesting a magic code."""
    email = serializers.EmailField(required=True)
    captcha_token = serializers.CharField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user with this email address.")
        return value
        
    def validate_captcha_token(self, value):
        # For development/testing environment:
        # The default reCAPTCHA key '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe' is Google's test key
        # that always returns success, regardless of the token provided
        
        # Check if we're using the Google test key
        is_test_key = settings.RECAPTCHA_SECRET_KEY == '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
        
        # Verify the captcha token with Google reCAPTCHA API
        recaptcha_response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': settings.RECAPTCHA_SECRET_KEY,
                'response': value,
            }
        ).json()
        
        if not recaptcha_response.get('success', False):
            # Log additional info in development to help debugging
            if is_test_key:
                print("Warning: reCAPTCHA validation failed despite using test key.")
                print(f"Response: {recaptcha_response}")
            
            raise serializers.ValidationError("Invalid CAPTCHA. Please try again.")
        
        return value

class MagicCodeVerifySerializer(serializers.Serializer):
    """Serializer for verifying a magic code."""
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        code = attrs.get('code')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No user with this email address."})
            
        magic_code = MagicCode.objects.filter(
            user=user,
            code=code,
            is_used=False
        ).order_by('-created_at').first()
        
        if not magic_code:
            raise serializers.ValidationError({"code": "Invalid or expired code."})
            
        if not magic_code.is_valid:
            raise serializers.ValidationError({"code": "Code has expired."})
            
        attrs['user'] = user
        attrs['magic_code'] = magic_code
        return attrs

class CheckUserSerializer(serializers.Serializer):
    """Serializer for checking if a user exists and getting their role."""
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user with this email address.")
        return value

# This serializer is no longer needed since all users will use magic code login
# Keeping it for reference but it won't be used
class AdminLoginSerializer(serializers.Serializer):
    """Serializer for admin/moderator login with magic code verification only."""
    email = serializers.EmailField(required=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No user with this email address."})
            
        # Check if user is admin or moderator
        if user.role not in ['ADMIN', 'MODERATOR']:
            raise serializers.ValidationError({"email": "This endpoint is only for admin or moderator users."})
            
        attrs['user'] = user
        return attrs 