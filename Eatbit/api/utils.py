import time
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

class ErrorConst:

    INVALID_EMAIL = "Invalid email address"
    INVALID_PASSWORD = "Invalid password format"
    INVALID_ROLE = "Invalid role"
    INVALID_STATUS= "Invalid Status"
    INVALID_OS= "Invalid OS"
    INVALID_TOKEN_TYPE= "Invalid Token Type"
    INVALID_DEVICE_TYPE= "Invalid Device Type"
    INVALID_COUNTRY_CODE = "Invalid country code"
    USER_ALREADY_EXIST= "User already exists"
    SOMETHING_WENT_WRONG = "Email is already registered"
    DEVICE_NOT_VALID= "Device is not valid"
    SESSION_NOT_DELETED_PROPERLY= "Sessions not deleted properly"
    SESSION_NOT_VALID= "Session is not valid"
    USER_REGISTERED_SUCCESSFULLY="User registered successfully"
    INVALID_DATA= "Invalid Data"
    INTERNAL_SERVER_ERROR= "Internal Server Error"

def refresh_utility_func(user):
    Refresh = RefreshToken.for_user(user)
    return {  
                'access' : str(Refresh.access_token),
                'refresh' : str(Refresh)
    } 

def json_response(success = False, status_code = status.HTTP_400_BAD_REQUEST, message='', error={}, result={} ):
    return Response({
        'success': success,
        'status_code': status_code,
        'message': message,
        'result': result,
        'error': error,
        'time': time.time()*1000
    }, status=status_code)