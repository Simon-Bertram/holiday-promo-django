from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import MagicCode

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the User model."""
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'role', 'is_verified', 'verified_at']
        read_only_fields = ['id', 'verified_at']

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(
        write_only=True, 
        required=True,
        validators=[validate_password]
    )
    password_confirm = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password_confirm', 'first_name', 'last_name']
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
        
    def create(self, validated_data):
        validated_data.pop('password_confirm')
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
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user with this email address.")
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