from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import uuid
import random
import string

class User(AbstractUser):
    """Custom user model with added role field for role-based access control and email verification."""
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', _('Admin')
        MODERATOR = 'MODERATOR', _('Moderator')
        USER = 'USER', _('User')
    
    email = models.EmailField(_('email address'), unique=True)
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.USER,
    )
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return self.email
    
    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN
    
    @property
    def is_moderator(self):
        return self.role == self.Role.MODERATOR
        
    @property
    def is_regular_user(self):
        return self.role == self.Role.USER
    
    def verify_email(self):
        """Mark the user's email as verified and record the timestamp."""
        self.is_verified = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_verified', 'verified_at'])


class MagicCode(models.Model):
    """Model to store magic codes for passwordless authentication."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='magic_codes')
    code = models.CharField(max_length=5)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Magic code for {self.user.email}"
    
    @property
    def is_valid(self):
        """Check if the magic code is still valid."""
        return (
            not self.is_used and 
            timezone.now() <= self.expires_at
        )

    @classmethod
    def generate_code(cls, user, expiry_minutes=10):
        """Generate a new 5-digit magic code for a user."""
        # Generate a random 5-digit number
        code = ''.join(random.choices(string.digits, k=5))
        
        # Invalidate any existing unused codes for this user
        cls.objects.filter(
            user=user,
            is_used=False
        ).update(is_used=True)
        
        # Create new code
        expires_at = timezone.now() + timezone.timedelta(minutes=expiry_minutes)
        return cls.objects.create(
            user=user,
            code=code,
            expires_at=expires_at
        )
