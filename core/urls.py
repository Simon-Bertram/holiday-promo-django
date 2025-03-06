from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    CustomTokenObtainPairView,
    UserRegistrationView,
    UserView,
    request_magic_code,
    verify_magic_code,
    verify_email,
    check_user_exists,
    admin_login,
    delete_user,
    get_user_count
)

app_name = 'core'

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/register/', UserRegistrationView.as_view(), name='register'),
    path('auth/check-user/', check_user_exists, name='check_user_exists'),
    path('auth/magic-code/request/', request_magic_code, name='request_magic_code'),
    path('auth/magic-code/verify/', verify_magic_code, name='verify_magic_code'),
    path('auth/admin-login/', admin_login, name='admin_login'),
    path('auth/verify-email/', verify_email, name='verify_email'),
    
    # User endpoints
    path('user/me/', UserView.as_view(), name='user_me'),
    path('user/delete/', delete_user, name='delete_user'),

    # Admin dashboard endpoints
    path('dashboard/user-count/', get_user_count, name='get_user_count'),
] 