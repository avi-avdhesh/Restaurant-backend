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
    INVALID_PHONE_NUMBER= "Invalid Phone Number"
    INVALID_COUNTRY_CODE = "Invalid country code"
    INVALID_OTP= "Invalid OTP"
    USER_ALREADY_EXIST= "User already exists"
    SOMETHING_WENT_WRONG = "Email is already registered"
    DEVICE_NOT_VALID= "Device is not valid"
    SESSION_NOT_DELETED_PROPERLY= "Sessions not deleted properly"
    SESSION_NOT_VALID= "Session is not valid"
    USER_REGISTERED_SUCCESSFULLY="User registered successfully"
    INVALID_DATA= "Invalid Data"
    INTERNAL_SERVER_ERROR= "Internal Server Error"
    DATA_UPDATED_SUCCESSFULLY="User Data Updated Successfully"
    USER_DELETED_SUCCESSFULLY="User deleted successfully"
    TOKEN_REQUIRED= "Refresh Token is required"
    LOG_OUT_SUCCESSFULL= "Successfully Logged Out"
    TOKEN_ERROR= "Token Error"
    UNEXPECTED_ERROR= "Unexpected Error"
    EMAIL_REQUIRED= "Email is required"
    EMAIL_DOESNT_EXIST ="User with the given email doesn't exist"
    OTP_SENT= "OTP sent at email"
    EMAIL_OTP_REQUIRED= "Email and Otp are required"
    OTP_EXPIRED="OTP has expired"
    OTP_VERIFIED= "OTP Verified succesfully"
    PASSWORD_RESET= "Password reset successfully"
    PASSWORD_CHANGED="Password changed successfully"
    WRONG_PASSWORD= "Wrong password"
    OLD_PASSWORD_REQUIRED= "Old Password is required"
    NEW_PASSWORD_REQUIRED= "New password is required"
    OTP_DOESNT_EXIST= "OTP doesn't exists!"
    FAILED_TO_SEND_OTP= "Failed to send OTP email."
    CATEGORY_EXISTS= "Category already exists!"
    CATEGORY_DOESNT_EXISTS= "Category does not exists!"
    CATEGORY_SAVED= "Category saved successfully"
    INVALID_CATEGORY_ID= "Invalid category ID"
    CATEGORY_UPDATED= "Category updated successfully"
    CATEGORY_DELETED= "Category deleted successfully"
    INVALID_SUB_CATEGORY_ID= "Invalid sub category ID"
    SUB_CATEGORY_EXISTS= "SubCategory already exists!"
    SUB_CATEGORY_DOESNT_EXISTS= "Sub-Category does not exists!"
    SUB_CATEGORY_SAVED= "Sub Category saved successfully"
    SUB_CATEGORY_UPDATED= "SubCategory updated successfully"
    SUB_CATEGORY_DELETED= "subCategory deleted successfully"
    ITEM_ADDED= "Item added successfully!"
    INVALID_ITEM_ID= "Invalid Item ID"
    ITEM_UPDATED= "Item updated successfully"
    ITEM_EXISTS="Item already exists!"
    ITEM_DOESNT_EXISTS="Item does not exists!"
    ITEM_DELETED= "Item deleted successfully!"
    ADD_ON_EXISTS= "Add On already exists for this item!"
    ADD_ON_SAVED= "Add On saved successfully"
    INVALID_ADD_ON_ID= "Invalid add on ID"
    ADD_ON_UPDATED= "Add On updated successfully"
    NEED_BOTH_NAME_ITEM_ID= "To update either name or item id, you need to provide both"
    ADD_ON_DELETED= "Add On deleted successfully"







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