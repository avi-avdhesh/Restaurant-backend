from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

class CustomTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')

        if not token:
            return None

        try:
            jwt_object = JWTAuthentication()
            validated_token = jwt_object.get_validated_token(token.split(" ")[1])
            current_user = jwt_object.get_user(validated_token)
        except Exception:
            raise AuthenticationFailed('Invalid Token')

        if not current_user:
            raise AuthenticationFailed('Invalid user')

        return (current_user, validated_token)
