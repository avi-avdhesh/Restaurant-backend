from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.exceptions import PermissionDenied

class IsAdminOrReadOnlyPublic(BasePermission):
    """
    Allow:
    - Anyone to GET
    - Only admin users to POST, PUT, PATCH, DELETE
    """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Login Required")

        if getattr(request.user, 'role', None) != 'admin':
            raise PermissionDenied("Only admin can perform this action")

        return True

class IsAdminOnly(BasePermission):
    def has_permission(self,request, view):
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Login Required")

        if getattr(request.user, 'role', None) != 'admin':
            raise PermissionDenied("Only admin can perform this action")
        return True    
        