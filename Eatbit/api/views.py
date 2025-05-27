from django.shortcuts import render
from .models import UserModel, UserSession, UserDevice
from .serializers import UserSerializer, DeviceSerializer, SessionSerializer, UserUpdateSerializer
from rest_framework.views import APIView
from django.db import transaction
from .validations import CheckValidations
from .authentication import CustomTokenAuthentication
from .utils import ErrorConst, refresh_utility_func, json_response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password


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
                if not CheckValidations.validate_phone(phone_no):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_PHONE_NUMBER)
                if not CheckValidations.validate_country_code(country_code):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_COUNTRY_CODE)
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

class UpdateUser(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]
    def put(self,request):
        try:
            with transaction.atomic():           
                user_id= request.user.id
                user= UserModel.objects.get(id=user_id)
                data= request.data
                name= data.get('name',None)
                email= data.get('email',None)
                phone_no = data.get('phone_no', None)
                country_code= data.get('country_code', None)
                role= data.get('role',None)
                
                required_fields={ 
                                    "Name" : name,
                                    "Email" : email,
                                    "Phone Number" : phone_no,
                                    "Country Code" : country_code,
                                    "Role" : role,
                                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if not CheckValidations.validate_email(email):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_EMAIL, error=ErrorConst.INVALID_EMAIL)
                if not CheckValidations.validate_phone(phone_no):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_PHONE_NUMBER)
                if not CheckValidations.validate_country_code(country_code):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_COUNTRY_CODE)
                # if not CheckValidations.validate_password(password):
                #     return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_PASSWORD, error=ErrorConst.INVALID_PASSWORD)
                if role:
                    if not CheckValidations.validate_role(role):
                        return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_ROLE, error=ErrorConst.INVALID_ROLE)
                email= email.lower()
                # (excluding current user for checking)
                if UserModel.objects.filter(email=email).exclude(id=user.id).exists():
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.SOMETHING_WENT_WRONG, error=ErrorConst.SOMETHING_WENT_WRONG)
                # if UserModel.objects.filter(username=username).exclude(id=user.id).exists():
                #     return json_response(
                #         status_code=status.HTTP_400_BAD_REQUEST,
                #         success=False,
                #         result={},
                #         message="Username already exists",
                #         error="Username already exists"
                #     )
                user_data= {
                            'name': name,
                            'phone_no': phone_no,
                            'email': email,
                            'country_code': country_code,
                            'role': role
                        }         
                serializer = UserUpdateSerializer(user, data=user_data, partial=False)
                if serializer.is_valid():
                    serializer.save()                
                    return json_response(success=True, result=serializer.data, message= ErrorConst.DATA_UPDATED_SUCCESSFULLY ,  status_code=status.HTTP_200_OK)
                return json_response(success=False, message= ErrorConst.INVALID_DATA ,error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=ErrorConst.INTERNAL_SERVER_ERROR, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self,request):
        with transaction.atomic():      
            user_id= request.user.id
            user= UserModel.objects.get(id=user_id)
            data = request.data
            name= data.get('name',None)
            email= data.get('email',None)
            phone_no = data.get('phone_no', None)
            country_code= data.get('country_code', None)
            role= data.get('role',None)
            
            if email:
                if not CheckValidations.validate_email(email):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_EMAIL, error=ErrorConst.INVALID_EMAIL)
                email= email.lower()
                if UserModel.objects.filter(email=email).exclude(id=user.id).exists():
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.SOMETHING_WENT_WRONG, error=ErrorConst.SOMETHING_WENT_WRONG)
            if role:
                if not CheckValidations.validate_role(role):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False,  result={}, message=ErrorConst.INVALID_ROLE, error=ErrorConst.INVALID_ROLE)    
            if phone_no:
                if not CheckValidations.validate_phone(phone_no):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_PHONE_NUMBER)
            if country_code:
                if not CheckValidations.validate_country_code(country_code):
                    return json_response(status_code=status.HTTP_400_BAD_REQUEST, success=False, result={}, message=ErrorConst.INVALID_COUNTRY_CODE)
            # if username:

                # (excluding current user for checking)
                # if UserModel.objects.filter(username=username).exclude(id=user.id).exists():
                #     return json_response(
                #         status_code=status.HTTP_400_BAD_REQUEST,
                #         success=False,
                #         result={},
                #         message="Username already exists",
                #         error="Username already exists"
                #     )
            user_data= {
                            'Name': name,
                            'Phone Number': phone_no,
                            'Email': email,
                            'Country Code': country_code,
                            'Role': role
                        }    
            user_data = {i:j for i,j in user_data.items() if j is not None}  

            serializer = UserUpdateSerializer(user, data=user_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return json_response(success=True, result=serializer.data, message=ErrorConst.DATA_UPDATED_SUCCESSFULLY ,status_code=status.HTTP_200_OK)
            return json_response(success=False, error=serializer.errors,message=ErrorConst.INVALID_DATA, status_code=status.HTTP_400_BAD_REQUEST)     
        
class DeleteUser(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]  

    def delete(self,request):
        try:
            user_id= request.user.id
            user = UserModel.objects.get(id=user_id)
            user.delete()

            return json_response(success=True,message =ErrorConst.USER_DELETED_SUCCESSFULLY, status_code=status.HTTP_200_OK)

        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):    
    def post(self,request):
        # try:
            data = request.data
            email= data.get('email')                      
            password= data.get('password')
            device_token = data.get('device_token', None)
            device_id = data.get('device_id', None)
            device_type = data.get('device_type', None)
            os = data.get('os', None) 
            required_fields = {"Email": email, "Password": password, "Device token" :device_token, "Device ID" : device_id, "Device Type" : device_type, "OS": os}
            if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                return validation_response
            user = UserModel.objects.filter(email= email).first()
            if user and check_password(password, user.password):
                tokens = refresh_utility_func(user)
                if not UserDevice.objects.filter(device_id = device_id, user_id=user.id).exists():
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
                        return json_response(success=False,message="Device is not valid", error=device_serializer.errors, result={}, status_code=status.HTTP_401_UNAUTHORIZED)
            # DELETING EXISTING SESSION
                try:
                    UserSession.objects.filter(device_id=device_serializer.data['id']).delete()
                except Exception as e:
                    return json_response(success=False, message="Sessions not deleted properly", error=str(e), result={}, status_code=status.HTTP_400_BAD_REQUEST)    
                
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
                    return json_response(success=False, message="Session is not valid", error=session_serializer.errors,result={},status_code=status.HTTP_401_UNAUTHORIZED)    
                return json_response(success=True, message="Login Successfull", result=tokens, status_code= status.HTTP_200_OK)
            return json_response(success=False, error="Invalid credentials", status_code= status.HTTP_401_UNAUTHORIZED)
        # except Exception as e:
        #     return json_response(success=False, message="Internal Server Error", error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserLogOut(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        try:
            user_id= request.user.id          
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return json_response(success=False, message=ErrorConst.TOKEN_REQUIRED, error=ErrorConst.TOKEN_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            UserSession.objects.filter(user_id=user_id).delete()
            return json_response(success=True, message=ErrorConst.LOG_OUT_SUCCESSFULL, result={},status_code=status.HTTP_200_OK)
        except TokenError as e:
            return json_response(success=False, error=str(e), message=ErrorConst.TOKEN_ERROR, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.UNEXPECTED_ERROR, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)