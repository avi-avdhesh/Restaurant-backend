from django.shortcuts import render
from .models import UserModel, UserSession, UserDevice
from .serializers import UserSerializer, DeviceSerializer, SessionSerializer
from rest_framework.views import APIView
from django.db import transaction
from .validations import CheckValidations
from .utils import ErrorConst, refresh_utility_func, json_response
from rest_framework import status
# Create your views here.

class RegisterUser(APIView):
    def post(self,request):
        try:
            with transaction.atomic():
                data= request.data
                email= data.get('email',None)
                name = data.get('name', None)
                password= data.get('password', None)
                phone_no= data.get('phone_no', None)
                role= data.get('role',None)
                country_code= data.get('country_code', None)
                device_token = data.get('device_token', None)
                device_id = data.get('device_id', None)
                device_type = data.get('device_type', None)
                os = data.get('os', None) 
                # token_type= data.get('token_type', None)
                required_fields={
                                "Email" : email,
                                "Name" : name,
                                "Password" : password,
                                "Phone No" : phone_no,
                                "Country Code" : country_code,
                                "Device Token": device_token,
                                "Device Id" : device_id,
                                "Device Type" : device_type,
                                "OS" : os,
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if not CheckValidations.validate_email(email):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_EMAIL, error=ErrorConst.INVALID_EMAIL)
                if not CheckValidations.validate_password(password):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_PASSWORD, error=ErrorConst.INVALID_PASSWORD)
                if role:
                    if not CheckValidations.validate_role(role):
                        return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_ROLE, error=ErrorConst.INVALID_ROLE)               
                # if status:
                #     if not CheckValidations.validate_status(status):
                #         return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS)
                # if token_type:
                #     if not CheckValidations.validate_token_type(token_type):
                #         return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_TOKEN_TYPE, error=ErrorConst.TOKEN_TYPE)
                if not CheckValidations.validate_device_type(device_type):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_DEVICE_TYPE, error=ErrorConst.INVALID_DEVICE_TYPE)
                if not CheckValidations.validate_os(os):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_OS, error=ErrorConst.INVALID_OS)               
                email= email.lower()
                if UserModel.objects.filter(email=email).exists():   
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.USER_ALREADY_EXIST, error=ErrorConst.USER_ALREADY_EXIST)
                # if UserModel.objects.filter(username=username).exists():
                #     return json_response(
                #         status_code=status.HTTP_400_BAD_REQUEST,
                #         success=False,
                #         result={},
                #         message="Username already exists",
                #         error="Username already exists"
                #     )
                user_data= {
                    'name': name,
                    'email': email,
                    'password': password,
                    'phone_no': phone_no,
                    'country_code':country_code,
                    'role': role,
                    # 'status' : status
                    }   
                user_data= {i:j for i,j in user_data.items() if j is not None}     
                serializer = UserSerializer(data=user_data)    
                if serializer.is_valid():
                    user = serializer.save() 
                    tokens= refresh_utility_func(user)  
                    # (deleting device if it exists already for other user)(depends upon requirement)
                    UserDevice.objects.filter(device_id= device_id).delete()
                    device_data= {
                        'user_id' : user.id,
                        'device_id' : device_id,
                        'device_token' : device_token,
                        'device_type': device_type,
                        'os' : os
                    }
                    device_serializer= DeviceSerializer(data= device_data)
                    if device_serializer.is_valid():
                        device= device_serializer.save()
                    else:
                        return json_response(success=False,message=ErrorConst.DEVICE_NOT_VALID, error=device_serializer.errors, result={}, status_code=status.HTTP_401_UNAUTHORIZED)
                    # DELETING EXISTING SESSION
                    try:
                        UserSession.objects.filter(device_id=device_serializer.data['id']).delete()
                    except Exception as e:
                        return json_response(success=False, message=ErrorConst.SESSION_NOT_DELETED_PROPERLY, error=str(e), result={}, status_code=status.HTTP_400_BAD_REQUEST)    
                    
                    session_data={
                        "user_id" : user.id,
                        "device_id" : device.id,
                        "access_token" : tokens.get('access'),
                        "refresh_token" : tokens.get('refresh'),
                    }
                    session_serializer= SessionSerializer(data=session_data)
                    if session_serializer.is_valid():
                        session_serializer.save()
                    else:
                        return json_response(success=False, message=ErrorConst.SESSION_NOT_VALID, error=session_serializer.errors,result={},status_code=status.HTTP_401_UNAUTHORIZED)    

                    response_data= {
                        "user_data":{
                            'id' : user.id,
                            'name': user.name,
                            'phone_no': user.phone_no,
                            'email': user.email,
                            'country_code': user.country_code,
                            'role': user.role,
                            # 'status' : user.status,
                            'created at': user.created_at,
                            'updated at' : user.updated_at,
                            'deleted at' : user.deleted_at
                        },
                        'token' : tokens    
                    } 
                    return json_response(success=True, status_code=status.HTTP_201_CREATED, result=response_data, message=ErrorConst.USER_REGISTERED_SUCCESSFULLY)
                return json_response(success=False, status_code= status.HTTP_400_BAD_REQUEST, error=serializer.errors, message=ErrorConst.INVALID_DATA) 
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)