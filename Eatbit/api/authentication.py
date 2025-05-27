from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

class CustomTokenAuthentication(BaseAuthentication):

    def authenticate(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
    
        if not token:
            raise AuthenticationFailed('Token not found')
        try:
            jwt_object = JWTAuthentication()
            validated_token = jwt_object.get_validated_token(
                token.split(" ")[1])
            current_user = jwt_object.get_user(validated_token)
        # except ExpiredSignatureError:
        #     raise AuthenticationFailed("Token has expired")
        except AuthenticationFailed as e:
            raise AuthenticationFailed('Invalid Token')
        if not current_user:
            raise AuthenticationFailed('Invalid user')
        request.cur_user = current_user
        return (current_user, validated_token)
        