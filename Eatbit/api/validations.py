import re
from django.core.validators import validate_email as django_validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.response import Response
import time


def json_response(success = False, status_code = status.HTTP_400_BAD_REQUEST, message='', error={}, result={} ):
    return Response({
        'success': success,
        'status_code': status_code,
        'message': message,
        'result': result,
        'error': error,
        'time': time.time()*1000
    }, status=status_code)

class CheckValidations:
    @staticmethod
    def check_missing_fields(required_fields):
        missing_fields= []
        for field_name, value in required_fields.items():
            if value in [None, '', []]:
                missing_fields.append(field_name)

        if missing_fields:     
                return json_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    success=False,
                    result={},
                    message= "Missing required fields: " + " , ".join(missing_fields),
                    error= "Missing fields: " + " , ".join(missing_fields)
                )
        return None

    @staticmethod
    def validate_email(email):
        try:
            django_validate_email(email)
            return True
        except DjangoValidationError:
            return False

    @staticmethod
    def validate_password(new_password, user=None):
        try:
            validate_password(new_password, user=user)
            return True, []
        except ValidationError as e:
            return False, e.messages

    # @staticmethod
    # def validate_password(password):
    #     # Example: at least 8 chars, 1 uppercase, 1 number
    #     pattern = r'^(?=.*[A-Z])(?=.*\d).{8,}$'
    #     return bool(re.match(pattern, password))

    @staticmethod
    def validate_role(role):
        from .models import Role  # adjust path if needed
        return role in Role.values

    @staticmethod
    def validate_status(status):
        from .models import Status  # adjust path if needed
        return status in Status.values 

    @staticmethod
    def validate_token_type(token_type):
        from .models import TokenType  # adjust path if needed
        return token_type in TokenType.values         
    
    @staticmethod
    def validate_device_type(device_type):
        from .models import DeviceType  # adjust path if needed
        return device_type in DeviceType.values  
    
    @staticmethod
    def validate_os(os):
        from .models import OS  # adjust path if needed
        return os in OS.values

    @staticmethod
    def validate_country_code(code):
        # Basic example: +1, +91, etc.
        return bool(re.match(r'^\+\d{1,4}$', code))

    @staticmethod
    def validate_phone(phone_no):
        # Basic example: 7 to 15 digits
        return bool(re.match(r'^\d{7,15}$', phone_no))



