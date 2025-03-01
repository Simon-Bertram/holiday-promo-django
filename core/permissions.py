from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    """
    Custom permission to only allow admin users to access the view.
    """
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.is_admin
        )

class IsStaffUser(permissions.BasePermission):
    """
    Custom permission to only allow staff users to access the view.
    """
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.is_staff_member or request.user.is_admin)
        )

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admins to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Check if user is the owner of the object (assuming obj has a user field)
        is_owner = hasattr(obj, 'user') and obj.user == request.user
        
        # Check if user is admin
        is_admin = request.user.is_admin
        
        # Read permissions are allowed to any authenticated user,
        # so we'll always allow GET, HEAD or OPTIONS requests
        if request.method in permissions.SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
            
        # Write permissions are only allowed to the owner or admin
        return is_owner or is_admin 