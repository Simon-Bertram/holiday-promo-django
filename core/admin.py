from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User, MagicCode

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Custom fields'), {'fields': ('role', 'is_verified', 'verified_at')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('email', 'username', 'first_name', 'last_name', 'role', 'is_verified', 'is_staff')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    list_filter = ('role', 'is_verified', 'is_staff', 'is_superuser', 'is_active')
    readonly_fields = ('verified_at',)
    
@admin.register(MagicCode)
class MagicCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at', 'expires_at', 'is_used')
    search_fields = ('user__email', 'code')
    list_filter = ('is_used', 'created_at')
    readonly_fields = ('code', 'created_at')
