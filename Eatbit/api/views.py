from django.shortcuts import render
from .models import UserModel, UserSession, UserDevice, Otp, Menu_category, Menu_sub_category, Menu_items, Menu_add_on_items, CartItem, Cart, Order, OrderItems
from .serializers import UserSerializer, DeviceSerializer, SessionSerializer, UserUpdateSerializer, OtpSerializer, MenuCategorySerializer, MenuSubCategorySerializer, MenuItemSerializer, MenuAddOnItemsSerializer, CartItemSerializer, CartSerializer, OrderSerializer, OrderItemsSerializer
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
import random
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import secrets
from django.core.mail import send_mail
from .permission import IsAdminOrReadOnlyPublic, IsAdminOnly
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# from uuid import UUID



# Create your views here.
class ListUsersView(APIView):
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [IsAdminOnly]

    def get(self, request):
        try:
            users = UserModel.objects.all()
            if not users.exists():
                return json_response(success=True,message=ErrorConst.NO_USERS_REGISTERED,result=[],status_code=status.HTTP_200_OK)
            serializer = UserSerializer(users, many=True)
            return json_response(success=True,
                message=ErrorConst.USERS_FETCHED,result=serializer.data,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False,message=ErrorConst.INTERNAL_SERVER_ERROR,error=str(e),status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class RetrieveUserView(APIView):
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Retrieve the currently authenticated user's profile information.",
        responses={
            200: openapi.Response(description="User profile retrieved successfully."),
            404: openapi.Response(description="User does not exist."),
            500: openapi.Response(description="Internal server error.")
        },
        tags=["User"]
    )
    def get(self, request):
        try:
            user=request.user
            user_exists= UserModel.objects.filter(id=user.id).exists()
            if not user or not user_exists:
                return json_response(success=False,message=ErrorConst.USER_DOESNT_EXIST,error=ErrorConst.USER_DOESNT_EXIST,status_code=status.HTTP_404_NOT_FOUND)
            serializer = UserSerializer(user)
            return json_response(success=True,message=ErrorConst.USER_PROFILE,result=serializer.data,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False,message=ErrorConst.INTERNAL_SERVER_ERROR,error=str(e),status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class RegisterUser(APIView):
    @swagger_auto_schema(
        operation_description="Register a new user with device information and receive JWT tokens.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[
                "email", "name", "password", "phone_no", "country_code",
                "device_token", "device_id", "device_type", "os"
            ],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="John Doe"),
                "password": openapi.Schema(type=openapi.TYPE_STRING, example="StrongP@ss123"),
                "phone_no": openapi.Schema(type=openapi.TYPE_STRING, example="9876543210"),
                "role": openapi.Schema(type=openapi.TYPE_STRING, example="user"),
                "country_code": openapi.Schema(type=openapi.TYPE_STRING, example="+91"),
                "device_token": openapi.Schema(type=openapi.TYPE_STRING, example="fcm_device_token_123"),
                "device_id": openapi.Schema(type=openapi.TYPE_STRING, example="device-uuid-xyz"),
                "device_type": openapi.Schema(type=openapi.TYPE_STRING, example="mobile"),
                "os": openapi.Schema(type=openapi.TYPE_STRING, example="android"),
            }
        ),
        responses={
            201: openapi.Response(description="User registered successfully, returns tokens and user info."),
            400: openapi.Response(description="Validation failed"),
            500: openapi.Response(description="Internal server error"),
        },
        tags=["User"]
    )
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
    @swagger_auto_schema(
        operation_description="Fully update the authenticated user's profile. All fields are required.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["name", "email", "phone_no", "country_code", "role"],
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="John Doe"),
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="john@example.com"),
                "phone_no": openapi.Schema(type=openapi.TYPE_STRING, example="9876543210"),
                "country_code": openapi.Schema(type=openapi.TYPE_STRING, example="+91"),
                "role": openapi.Schema(type=openapi.TYPE_STRING, example="user"),
            }
        ),
        responses={
            200: openapi.Response(description="User updated successfully."),
            400: openapi.Response(description="Invalid data."),
            500: openapi.Response(description="Internal server error.")
        },
        tags=["User"]
    )
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
    
    @swagger_auto_schema(
        operation_description="Partially update the authenticated user's profile. Only send fields you want to change.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="John Doe"),
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="john@example.com"),
                "phone_no": openapi.Schema(type=openapi.TYPE_STRING, example="9876543210"),
                "country_code": openapi.Schema(type=openapi.TYPE_STRING, example="+91"),
                "role": openapi.Schema(type=openapi.TYPE_STRING, example="user"),
            }
        ),
        responses={
            200: openapi.Response(description="User partially updated successfully."),
            400: openapi.Response(description="Invalid data."),
            500: openapi.Response(description="Internal server error.")
        },
        tags=["User"]
    )
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
    
    @swagger_auto_schema(
        operation_description="Delete the currently authenticated user.",
        responses={
            200: openapi.Response(description="User deleted successfully."),
            500: openapi.Response(description="Internal server error."),
        },
        tags=["User"]
    )
    def delete(self,request):
        try:
            user_id= request.user.id
            user = UserModel.objects.get(id=user_id)
            user.delete()

            return json_response(success=True,message =ErrorConst.USER_DELETED_SUCCESSFULLY, status_code=status.HTTP_200_OK)

        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):  
    @swagger_auto_schema(
        operation_description="User login with email and password, along with device details",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "password", "device_token", "device_id", "device_type", "os"],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, example="avdesh@appventurez.com"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, example="avi@12345"),
                'device_token': openapi.Schema(type=openapi.TYPE_STRING, example="abcd1234token"),
                'device_id': openapi.Schema(type=openapi.TYPE_STRING, example="device-001"),
                'device_type': openapi.Schema(type=openapi.TYPE_STRING, example="mobile"),
                'os': openapi.Schema(type=openapi.TYPE_STRING, example="android"),
            },
        ),
        responses={
            200: openapi.Response(description="Login successful. JWT token returned."),
            401: openapi.Response(description="Invalid credentials or invalid device/session."),
            400: openapi.Response(description="Validation or session error"),
        },
        tags=["User"]
    )
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
                device=UserDevice.objects.filter(device_id = device_id, user_id=user.id).first()
                if not device:
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
                        UserSession.objects.filter(device_id=device.id).delete()                    
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
    @swagger_auto_schema(
        operation_description="Logout the current user by blacklisting the refresh token and deleting their session.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["refresh"],
            properties={
                "refresh": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Refresh token to be blacklisted",
                    example="your_refresh_token_here"
                )
            }
        ),
        responses={
            200: openapi.Response(description="Logout successful."),
            400: openapi.Response(description="Token error or refresh token missing."),
        },
        tags=["User"]
    )
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

class ForgetPassword(APIView):
    @swagger_auto_schema(
        operation_description="Send an OTP to user's email for password reset.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email"],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
            }
        ),
        responses={
            200: openapi.Response(description="OTP sent successfully."),
            400: openapi.Response(description="Email is required or OTP sending failed."),
            404: openapi.Response(description="Email does not exist."),
        },
        tags=["User"]
    )
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return json_response(success=False, message=ErrorConst.EMAIL_REQUIRED ,error=ErrorConst.EMAIL_REQUIRED, status_code= status.HTTP_400_BAD_REQUEST)        
        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return json_response(success=False,message=ErrorConst.EMAIL_DOESNT_EXIST, error=ErrorConst.EMAIL_DOESNT_EXIST, status_code=status.HTTP_404_NOT_FOUND) 
        # otp = random.randint(100000,999999)
        otp = secrets.randbelow(900000) + 100000  # ensures 6-digit secure OTP
        expiry_time= timezone.now() + timedelta(minutes=10)
        # (this constant 10 minutes can be variable saved in settings)
        # otp_data= {
        #             "user_id" : user.id,
        #             "otp" : otp,
        #             "expiry_time" : expiry_time,
        #         }
        # otp_serializer= OtpSerializer(data=otp_data)
        # if otp_serializer.is_valid():
        #     otp_serializer.save()
        # else:
        #     return json_response(success=False, message=ErrorConst.INVALID_DATA, error=otp_serializer.errors, status=status.HTTP_400_BAD_REQUEST )    
        try:
            with transaction.atomic():
                Otp.objects.update_or_create(
                user_id=user,
                defaults={"otp": otp, "expiry_time": expiry_time}
                )

                send_mail(
                    subject= "OTP Verification",
                    message= f'Your OTP code is {otp}. It will expire at 10 minutes.',
                    from_email= settings.EMAIL_HOST_USER,
                    recipient_list= [email],
                    fail_silently= False,
                )
                return json_response(success=True, message=ErrorConst.OTP_SENT, status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False,error=str(e), message=ErrorConst.FAILED_TO_SEND_OTP, status_code=status.HTTP_400_BAD_REQUEST)

class OtpVerify(APIView):
    @swagger_auto_schema(
        operation_description="Verify the OTP sent to user's email for password reset or authentication.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "otp"],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                "otp": openapi.Schema(type=openapi.TYPE_INTEGER, example=123456),
            }
        ),
        responses={
            200: openapi.Response(description="OTP verified successfully."),
            400: openapi.Response(description="Missing or invalid OTP/email, or OTP expired."),
            404: openapi.Response(description="Email or OTP not found."),
        },
        tags=["User"]
    )
    def post(self,request):
        otp = request.data.get("otp")
        email = request.data.get("email")
        if not otp or not email:
            return json_response(success=False, error=ErrorConst.EMAIL_OTP_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)            
        try:     
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return json_response(success=False, error= ErrorConst.EMAIL_DOESNT_EXIST, status_code=status.HTTP_404_NOT_FOUND)

        try:
            user_otp = Otp.objects.get(user_id=user.id)
        except Otp.DoesNotExist:
            return json_response(success=False, error= ErrorConst.OTP_DOESNT_EXIST, status_code=status.HTTP_404_NOT_FOUND)  

        if int(user_otp.otp) != int(otp):
            return json_response(success=False, error=ErrorConst.INVALID_OTP, status_code=status.HTTP_400_BAD_REQUEST)
        
        if user_otp.expiry_time < timezone.now():
            return json_response(success=False, error=ErrorConst.OTP_EXPIRED, status_code=status.HTTP_400_BAD_REQUEST)
        user_otp.delete()
        return json_response(success=True, message=ErrorConst.OTP_VERIFIED, status_code=status.HTTP_200_OK)

class ResetPassword(APIView):
    @swagger_auto_schema(
        operation_description="Reset the user's password using their email and a new password after OTP verification.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "new_password"],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                "new_password": openapi.Schema(type=openapi.TYPE_STRING, example="NewSecureP@ssword123"),
                # You can uncomment this if you re-enable confirm_password
                # "confirm_password": openapi.Schema(type=openapi.TYPE_STRING, example="NewSecureP@ssword123"),
            }
        ),
        responses={
            200: openapi.Response(description="Password reset successful."),
            400: openapi.Response(description="Validation errors or user not found."),
        },
        tags=["User"]
    )
    def post(self,request):
        new_password= request.data.get("new_password")
        # confirm_password= request.data.get("confirm_password")
        # if not all([new_password, confirm_password]):
        #     return Response({"error" : "New Passowrd, Confirm Password are required"}, status=status.HTTP_400_BAD_REQUEST)
        # if new_password != confirm_password:
        #     return Response({"error" : "Passwords doesn't match"}, status=status.HTTP_400_BAD_REQUEST)
        
        email = request.data.get('email')
        if not email:
            return json_response(success=False, message=ErrorConst.EMAIL_REQUIRED, error= ErrorConst.EMAIL_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        if not new_password:
            return json_response(success=False, message=ErrorConst.NEW_PASSWORD_REQUIRED, error= ErrorConst.NEW_PASSWORD_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            user= UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return json_response(success=False,message=ErrorConst.EMAIL_DOESNT_EXIST, error= ErrorConst.EMAIL_DOESNT_EXIST, status_code=status.HTTP_400_BAD_REQUEST)
        
        is_valid, errors= CheckValidations.validate_password(new_password, user)
        if not is_valid:
            return json_response(success=False, error=errors, message=ErrorConst.INVALID_PASSWORD, status_code=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        return json_response(success=True, message= ErrorConst.PASSWORD_RESET, status_code=status.HTTP_200_OK)

class ChangePassword(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Change the authenticated user's password by providing the old and new passwords.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["old_password", "new_password"],
            properties={
                "old_password": openapi.Schema(type=openapi.TYPE_STRING, example="OldPassword123"),
                "new_password": openapi.Schema(type=openapi.TYPE_STRING, example="NewSecureP@ssword456"),
            }
        ),
        responses={
            200: openapi.Response(description="Password changed successfully."),
            400: openapi.Response(description="Invalid old password or validation error."),
        },
        tags=["User"]
    )
    def post(self,request):
        user= request.user
        old_password= request.data.get("old_password")
        new_password= request.data.get("new_password")
        if not new_password:
            return json_response(success=False, message=ErrorConst.NEW_PASSWORD_REQUIRED, error=ErrorConst.NEW_PASSWORD_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        if not old_password:
            return json_response(success=False, message=ErrorConst.OLD_PASSWORD_REQUIRED, error=ErrorConst.OLD_PASSWORD_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(old_password):
            return json_response(success=False, message=ErrorConst.WRONG_PASSWORD, error=ErrorConst.WRONG_PASSWORD, status_code=status.HTTP_400_BAD_REQUEST)
        is_valid, errors= CheckValidations.validate_password(new_password, user)
        if not is_valid:
            return json_response(success=False, error=errors, message=ErrorConst.INVALID_PASSWORD, status_code=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        return json_response(success=True, message=ErrorConst.PASSWORD_CHANGED, status_code=status.HTTP_200_OK)

class MenuCategoryAdd(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 

    @swagger_auto_schema(
        operation_description="Create a new menu category.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["name"],
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="Beverages"),
                "status": openapi.Schema(type=openapi.TYPE_STRING, example="active")
            }
        ),
        responses={201: "Created", 400: "Validation error"},
        tags=["Restaurant"]
    )
    def post(self,request):
        try:
            with transaction.atomic():
                data= request.data
                name=data.get("name",None)
                statusField=data.get("status", None)
                required_fields= {
                    "Name": name
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if Menu_category.objects.filter(name=name).exists():
                    return json_response(success=False, message=ErrorConst.CATEGORY_EXISTS, error=ErrorConst.CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                category_data={
                    "name" : name,
                    "status" : statusField
                }
                category_data= {i:j for i,j in category_data.items() if j is not None}
                serializer= MenuCategorySerializer(data=category_data)
                if serializer.is_valid():
                    category= serializer.save()
                    response_data= {
                        "id" : category.id,
                        "name" : category.name,
                        "status" : category.status,
                        "created_at" : category.created_at,
                        "updated_at" : category.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.CATEGORY_SAVED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MenuCategoryList(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Get list of all menu categories",
        responses={
            200: openapi.Response("List of categories", MenuCategorySerializer(many=True)),
            500: openapi.Response("Internal Server Error"),
        },
        tags= ["Restaurant"]
    )
    def get(self, request):
        try:
            categories = Menu_category.objects.all()
            serializer = MenuCategorySerializer(categories, many=True)
            return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)



class MenuCategory(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 

    @swagger_auto_schema(
        operation_description="Get all menu categories or a specific category by ID.",
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_INTEGER, required=True)
        ],
        responses={200: "Success", 400: "Invalid ID"},
        tags=["Restaurant"]
    )
    def get(self, request, id=None):
        try:
            if id:
                try:
                    category = Menu_category.objects.get(id=id)
                except Menu_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_CATEGORY_ID, error=ErrorConst.INVALID_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                serializer = MenuCategorySerializer(category)
                return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
            else:
                return json_response(success=False, message=ErrorConst.CATEGORY_REQUIRED, error=ErrorConst.CATEGORY_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Update a category completely by ID.",
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_INTEGER, required=True)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["name"],
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="Main Course"),
                "status": openapi.Schema(type=openapi.TYPE_STRING, example="inactive")
            }
        ),
        responses={200: "Updated", 400: "Validation error"},
        tags=["Restaurant"]
    )
    def put(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   category= Menu_category.objects.get(id=id)
                except Menu_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_CATEGORY_ID, error=ErrorConst.INVALID_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                
                data= request.data
                name=data.get("name",None)
                statusField=data.get("status", None)
                required_fields= {
                    "Name": name
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if Menu_category.objects.filter(name=name).exclude(id=category.id).exists():
                    return json_response(success=False, message=ErrorConst.CATEGORY_EXISTS, error=ErrorConst.CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                category_data={
                    "name" : name,
                    "status" : statusField
                }
                category_data= {i:j for i,j in category_data.items() if j is not None}

                serializer= MenuCategorySerializer(category, data=category_data)  
                if serializer.is_valid():
                    update_category= serializer.save()
                    response_data= {
                        "id" : update_category.id,
                        "name" : update_category.name,
                        "status" : update_category.status,
                        "created_at" : update_category.created_at,
                        "updated_at" : update_category.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.CATEGORY_UPDATED, result=response_data, status_code=status.HTTP_200_OK)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Partially update a category by ID.",
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_INTEGER , required=True)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING, example="Snacks"),
                "status": openapi.Schema(type=openapi.TYPE_STRING, example="active")
            }
        ),
        responses={200: "Updated", 400: "Validation error"},
        tags=["Restaurant"]
    )
    def patch(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   category= Menu_category.objects.get(id=id)
                except Menu_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_CATEGORY_ID, error=ErrorConst.INVALID_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                data= request.data
                name=data.get("name",None)
                statusField=data.get("status", None)
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if name:
                    if Menu_category.objects.filter(name=name).exclude(id=category.id).exists():
                        return json_response(success=False, message=ErrorConst.CATEGORY_EXISTS, error=ErrorConst.CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                category_data={
                    "name" : name,
                    "status" : statusField
                }
                category_data= {i:j for i,j in category_data.items() if j is not None}

                serializer= MenuCategorySerializer(category,data=category_data, partial=True)  
                if serializer.is_valid():
                    update_category= serializer.save()
                    response_data= {
                        "id" : update_category.id,
                        "name" : update_category.name,
                        "status" : update_category.status,
                        "created_at" : update_category.created_at,
                        "updated_at" : update_category.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.CATEGORY_UPDATED, result=response_data, status_code=status.HTTP_200_OK)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Delete a menu category by ID.",
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_INTEGER, required=True)
        ],
        responses={200: "Deleted", 400: "Invalid ID"},
        tags=["Restaurant"]
    )
    def delete(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   category= Menu_category.objects.get(id=id)
                except Menu_category.DoesNotExist:
                   return json_response(success=False, message=ErrorConst.INVALID_CATEGORY_ID, error=ErrorConst.INVALID_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                category.delete()
                return json_response(success=True, message=ErrorConst.CATEGORY_DELETED,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
class MenuSubCategoryAdd(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Create a new subcategory under a given category",
        request_body=MenuSubCategorySerializer,
        responses={
            201: openapi.Response(description="Subcategory created successfully"),
            400: openapi.Response(description="Invalid data or subcategory already exists"),
            500: openapi.Response(description="Internal server error"),
        },
        tags=["Restaurant"]
    )
    def post(self,request):
            try:
                with transaction.atomic():
                    data=request.data
                    name= data.get("name",None)
                    category_id= data.get("category_id", None)
                    statusField= data.get("status", None)
                    required_fields= {
                        "Name": name,
                        "Category Id" : category_id
                    }
                    if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                        return validation_response
                    if statusField:
                        if not CheckValidations.validate_status(statusField):
                            return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                    if Menu_sub_category.objects.filter(name=name).exists():
                        return json_response(success=False, message=ErrorConst.CATEGORY_EXISTS, error=ErrorConst.CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                    
                    if not Menu_category.objects.filter(id=category_id).exists():
                            return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                    sub_category_data={
                        "name" : name,
                        "category_id" : category_id,
                        "status" : statusField
                    }
                    sub_category_data= {i:j for i,j in sub_category_data.items() if j is not None}
                    serializer= MenuSubCategorySerializer(data=sub_category_data)
                    if serializer.is_valid():
                        sub_category= serializer.save()
                        response_data= {
                            "id" : sub_category.id,
                            "name" : sub_category.name,
                            "category_id" : sub_category.category_id_id,
                            "status" : sub_category.status,
                            "created_at" : sub_category.created_at,
                            "updated_at" : sub_category.updated_at
                        }
                        return json_response(success=True, message=ErrorConst.SUB_CATEGORY_SAVED, result=response_data, status_code=status.HTTP_201_CREATED)
                    return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuSubCategoryList(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Get list of all subcategories",
        responses={
            200: openapi.Response("List of subcategories", MenuSubCategorySerializer(many=True)),
            500: openapi.Response("Internal Server Error")
        },
        tags=["Restaurant"]
    )
    def get(self,request):
        try:
            subcategories = Menu_sub_category.objects.all()
            serializer = MenuSubCategorySerializer(subcategories, many=True)
            return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)   
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuSubCategory(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Retrieve a menu subcategory by ID",
        manual_parameters=[
            openapi.Parameter(
                'id', openapi.IN_PATH, description="UUID of the subcategory", type=openapi.TYPE_STRING, required=True
            )
        ],
        responses={
            200: openapi.Response("Success", MenuSubCategorySerializer),
            400: "Bad Request",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def get(self, request, id=None):
        try:
            if id:
                try:
                    subcategory = Menu_sub_category.objects.get(id=id)
                except Menu_sub_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_SUB_CATEGORY_ID, error=ErrorConst.INVALID_SUB_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                serializer = MenuSubCategorySerializer(subcategory)
                return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
            else:
                return json_response(success=False, message=ErrorConst.SUBCATEGORY_REQUIRED, error=ErrorConst.SUBCATEGORY_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Fully update a menu subcategory by ID",
        manual_parameters=[
            openapi.Parameter(
                'id', openapi.IN_PATH, description="UUID of the subcategory", type=openapi.TYPE_STRING, required=True
            )
        ],
        request_body=MenuSubCategorySerializer,
        responses={
            200: openapi.Response("Updated successfully"),
            400: "Invalid data or conflict",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )         
    def put(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   sub_category= Menu_sub_category.objects.get(id=id)
                except Menu_sub_category.DoesNotExist:
                   return json_response(success=False, message=ErrorConst.INVALID_SUB_CATEGORY_ID, error=ErrorConst.INVALID_SUB_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                
                data= request.data
                name=data.get("name",None)
                category_id= data.get("category_id", None)
                statusField=data.get("status", None)
                required_fields= {
                    "Name": name,
                    "Category Id" : category_id
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if Menu_sub_category.objects.filter(name=name).exclude(id=sub_category.id).exists():
                    return json_response(success=False, message=ErrorConst.SUB_CATEGORY_EXISTS, error=ErrorConst.SUB_CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if not Menu_category.objects.filter(id=category_id).exists():
                        return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                sub_category_data={
                    "name" : name,
                    "category_id" : category_id,
                    "status" : statusField
                }
                sub_category_data= {i:j for i,j in sub_category_data.items() if j is not None}

                serializer= MenuSubCategorySerializer(sub_category, data=sub_category_data)  
                if serializer.is_valid():
                    update_sub_category= serializer.save()
                    response_data= {
                        "id" : update_sub_category.id,
                        "name" : update_sub_category.name,
                        "category_id" : update_sub_category.category_id_id,
                        "status" : update_sub_category.status,
                        "created_at" : update_sub_category.created_at,
                        "updated_at" : update_sub_category.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.SUB_CATEGORY_UPDATED, result=response_data, status_code=status.HTTP_200_OK)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
    @swagger_auto_schema(
        operation_description="Partially update a menu subcategory by ID",
        manual_parameters=[
            openapi.Parameter(
                'id', openapi.IN_PATH, description="UUID of the subcategory", type=openapi.TYPE_STRING, required=True
            )
        ],
        request_body=MenuSubCategorySerializer,
        responses={
            200: openapi.Response("Updated successfully"),
            400: "Invalid data or conflict",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def patch(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   sub_category= Menu_sub_category.objects.get(id=id)
                except Menu_sub_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_SUB_CATEGORY_ID, error=ErrorConst.INVALID_SUB_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                data= request.data
                name=data.get("name",None)
                category_id= data.get("category_id", None)
                statusField=data.get("status", None)
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if name:
                    if Menu_sub_category.objects.filter(name=name).exclude(id=sub_category.id).exists():
                        return json_response(success=False, message=ErrorConst.SUB_CATEGORY_EXISTS, error=ErrorConst.SUB_CATEGORY_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                if category_id:
                    if not Menu_category.objects.filter(id=category_id).exists():
                        return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                sub_category_data={
                    "name" : name,
                    "category_id" : category_id,
                    "status" : statusField
                }
                sub_category_data= {i:j for i,j in sub_category_data.items() if j is not None}

                serializer= MenuSubCategorySerializer(sub_category,data=sub_category_data, partial=True)  
                if serializer.is_valid():
                    update_sub_category= serializer.save()
                    response_data= {
                        "id" : update_sub_category.id,
                        "name" : update_sub_category.name,
                        "category_id" : update_sub_category.category_id_id,
                        "status" : update_sub_category.status,
                        "created_at" : update_sub_category.created_at,
                        "updated_at" : update_sub_category.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.SUB_CATEGORY_UPDATED, result=response_data, status_code=status.HTTP_200_OK)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Delete a menu subcategory by ID",
        manual_parameters=[
            openapi.Parameter(
                'id', openapi.IN_PATH, description="UUID of the subcategory", type=openapi.TYPE_STRING, required=True
            )
        ],
        responses={
            200: "Deleted successfully",
            400: "Invalid ID",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def delete(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   sub_category= Menu_sub_category.objects.get(id=id)
                except Menu_sub_category.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_SUB_CATEGORY_ID, error=ErrorConst.INVALID_SUB_CATEGORY_ID, status_code=status.HTTP_400_BAD_REQUEST)
                sub_category.delete()
                return json_response(success=True, message=ErrorConst.SUB_CATEGORY_DELETED,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuItemAdd(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic]
    
    @swagger_auto_schema(
        operation_description="Add a new menu item",
        request_body=MenuItemSerializer,
        responses={
            201: openapi.Response("Item added successfully"),
            400: "Invalid input or item already exists",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def post(self,request):
        try:
            with transaction.atomic():
                data=request.data
                name= data.get("name",None)
                desc= data.get("desc",None)
                image_url= data.get("image_url",None)
                price= data.get("price",None)
                category_id= data.get("category_id",None)
                sub_category_id= data.get("sub_category_id", None)
                statusField= data.get("status", None)
                required_fields= {
                    "Name": name,
                    "Description" : desc,
                    "Image URL" : image_url,
                    "Price" : price,
                    "Category Id" : category_id,
                    "Sub-Category" : sub_category_id
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if not Menu_category.objects.filter(id=category_id).exists():
                    return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if not Menu_sub_category.objects.filter(id=sub_category_id).exists():
                    return json_response(success=False, message=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, error=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if Menu_items.objects.filter(name=name).exists():
                    return json_response(success=False, message=ErrorConst.ITEM_EXISTS, error=ErrorConst.ITEM_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                item_data={
                    "name" : name,
                    "desc" : desc,
                    "image_url" : image_url,
                    "price" : price,
                    "category_id" : category_id,
                    "sub_category_id": sub_category_id,
                    "status" : statusField
                }
                item_data= {i:j for i,j in item_data.items() if j is not None}
                serializer= MenuItemSerializer(data=item_data)
                if serializer.is_valid():
                    item= serializer.save()
                    response_data= {
                        "id" : item.id,
                        "name" : item.name,
                        "desc" : item.desc,
                        "image_url" : item.image_url,
                        "price" : item.price,
                        "category_id" : item.category_id_id,
                        "sub_category_id" : item.sub_category_id_id,
                        "status" : item.status,
                        "created_at" : item.created_at,
                        "updated_at" : item.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ITEM_ADDED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuItemsList(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Retrieve a list of all menu items",
        responses={
            200: openapi.Response("List of menu items", MenuItemSerializer(many=True)),
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def get(self,request):
        try:
            item = Menu_items.objects.all()
            serializer = MenuItemSerializer(item, many=True)
            return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)       
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuItems(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Retrieve a single menu item by ID",
        responses={
            200: openapi.Response("Menu item retrieved successfully", MenuItemSerializer),
            400: "Invalid item ID",
            500: "Internal Server Error"
        },
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_PATH, description="Menu item ID", type=openapi.TYPE_STRING)
        ],
        tags=["Restaurant"]
    )
    def get(self, request, id=None):
        try:
            if id:
                try:
                    item = Menu_items.objects.get(id=id)
                except Menu_items.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_ITEM_ID, error=ErrorConst.INVALID_ITEM_ID, status_code=status.HTTP_400_BAD_REQUEST)
                serializer = MenuItemSerializer(item)
                return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
            else:
                return json_response(sucess=False, message= ErrorConst.ITEM_ID_REQUIRED, error=ErrorConst.ITEM_ID_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Update a menu item completely",
        request_body=MenuItemSerializer,
        responses={
            201: openapi.Response("Item updated successfully", MenuItemSerializer),
            400: "Invalid data",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def put(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   item= Menu_items.objects.get(id=id)
                except Menu_items.DoesNotExist:
                   return json_response(success=False, message=ErrorConst.INVALID_ITEM_ID, error=ErrorConst.INVALID_ITEM_ID, status_code=status.HTTP_400_BAD_REQUEST)
                
                data=request.data
                name= data.get("name",None)
                desc= data.get("desc",None)
                image_url= data.get("image_url",None)
                price= data.get("price",None)
                category_id= data.get("category_id",None)
                sub_category_id= data.get("sub_category_id", None)
                statusField= data.get("status", None)
                required_fields= {
                    "Name": name,
                    "Description" : desc,
                    "Image URL" : image_url,
                    "Price" : price,
                    "Category Id" : category_id,
                    "Sub-Category" : sub_category_id
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if not Menu_category.objects.filter(id=category_id).exists():
                    return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if not Menu_sub_category.objects.filter(id=sub_category_id).exists():
                    return json_response(success=False, message=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, error=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if Menu_items.objects.filter(name=name).exclude(id=item.id).exists():
                    return json_response(success=False, message=ErrorConst.ITEM_EXISTS, error=ErrorConst.ITEM_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                item_data={
                    "name" : name,
                    "desc" : desc,
                    "image_url" : image_url,
                    "price" : price,
                    "category_id" : category_id,
                    "sub_category_id": sub_category_id,
                    "status" : statusField
                }
                item_data= {i:j for i,j in item_data.items() if j is not None}
                serializer= MenuItemSerializer(item, data=item_data)
                if serializer.is_valid():
                    item= serializer.save()
                    response_data= {
                        "id" : item.id,
                        "name" : item.name,
                        "desc" : item.desc,
                        "image_url" : item.image_url,
                        "price" : item.price,
                        "category_id" : item.category_id_id,
                        "sub_category_id" : item.sub_category_id_id,
                        "status" : item.status,
                        "created_at" : item.created_at,
                        "updated_at" : item.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ITEM_UPDATED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Partially update a menu item",
        request_body=MenuItemSerializer,
        responses={
            200: openapi.Response("Item updated successfully", MenuItemSerializer),
            400: "Invalid data",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def patch(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   item= Menu_items.objects.get(id=id)
                except Menu_items.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_ITEM_ID, error=ErrorConst.INVALID_ITEM_ID, status_code=status.HTTP_400_BAD_REQUEST)
                data=request.data
                name= data.get("name",None)
                desc= data.get("desc",None)
                image_url= data.get("image_url",None)
                price= data.get("price",None)
                category_id= data.get("category_id",None)
                sub_category_id= data.get("sub_category_id", None)
                statusField= data.get("status", None)

                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                if sub_category_id:
                    if not Menu_sub_category.objects.filter(id=sub_category_id).exists():
                        return json_response(success=False, message=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, error=ErrorConst.SUB_CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                if category_id:
                    if not Menu_category.objects.filter(id=category_id).exists():
                        return json_response(success=False, message=ErrorConst.CATEGORY_DOESNT_EXISTS, error=ErrorConst.CATEGORY_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                if Menu_items.objects.filter(name=name).exclude(id=item.id).exists():
                    return json_response(success=False, message=ErrorConst.ITEM_EXISTS, error=ErrorConst.ITEM_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)  
                item_data={
                    "name" : name,
                    "desc" : desc,
                    "image_url" : image_url,
                    "price" : price,
                    "category_id" : category_id,
                    "sub_category_id": sub_category_id,
                    "status" : statusField
                }
                item_data= {i:j for i,j in item_data.items() if j is not None}

                serializer= MenuItemSerializer(item,data=item_data, partial=True)  
                if serializer.is_valid():
                    update_item= serializer.save()
                    response_data= {
                        "id" : update_item.id,
                        "name" : update_item.name,
                        "category_id" : update_item.category_id_id,
                        "status" : update_item.status,
                        "created_at" : update_item.created_at,
                        "updated_at" : update_item.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ITEM_UPDATED, result=response_data, status_code=status.HTTP_200_OK)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Delete a menu item",
        responses={
            200: "Item deleted successfully",
            400: "Invalid item ID",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def delete(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   item= Menu_items.objects.get(id=id)
                except Menu_items.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_ITEM_ID, error=ErrorConst.INVALID_ITEM_ID, status_code=status.HTTP_400_BAD_REQUEST)
                item.delete()
                return json_response(success=True, message=ErrorConst.ITEM_DELETED,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuAddOnItemAdd(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Add a new menu add-on item",
        request_body=MenuAddOnItemsSerializer,
        responses={
            201: openapi.Response("Add-on item created", MenuAddOnItemsSerializer),
            400: "Invalid data or duplicate add-on",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def post(self,request):
        try:
            with transaction.atomic():
                data=request.data
                name= data.get("name",None)
                menu_items= data.get("menu_items_id", None)
                price= data.get("price", None)
                statusField= data.get("status", None)
                required_fields= {
                    "Name": name,
                    "Item Id" : menu_items,
                    "Price" : price,
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                
                if Menu_add_on_items.objects.filter(name=name, menu_items=menu_items).exists():
                    return json_response(success=False, message=ErrorConst.ADD_ON_EXISTS, error=ErrorConst.ADD_ON_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if not Menu_items.objects.filter(id=menu_items).exists():
                    return json_response(success=False, message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                add_on_data={
                    "name" : name,
                    "menu_items" : menu_items,
                    "price" : price,
                    "status" : statusField
                }
                add_on_data= {i:j for i,j in add_on_data.items() if j is not None}
                serializer= MenuAddOnItemsSerializer(data=add_on_data)
                if serializer.is_valid():
                    add_on= serializer.save()
                    response_data= {
                        "id" : add_on.id,
                        "name" : add_on.name,
                        "price" : add_on.price,
                        "menu_items" : add_on.menu_items_id,
                        "status" : add_on.status,
                        "created_at" : add_on.created_at,
                        "updated_at" : add_on.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ADD_ON_SAVED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuAddOnItemList(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Retrieve a list of all menu add-on items",
        responses={
            200: openapi.Response("Success", MenuAddOnItemsSerializer(many=True)),
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def get(self,request):
        try:
            add_on = Menu_add_on_items.objects.all()
            serializer = MenuAddOnItemsSerializer(add_on, many=True)
            return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MenuAddOnItem(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAdminOrReadOnlyPublic] 
    
    @swagger_auto_schema(
        operation_description="Retrieve a single add-on item by ID",
        manual_parameters=[openapi.Parameter('id', openapi.IN_PATH, description="Add-on ID", type=openapi.TYPE_STRING, required=True)],
        responses={
            200: openapi.Response("Success", MenuAddOnItemsSerializer),
            400: "Invalid or missing ID",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def get(self, request, id=None):
        try:
            if id:
                try:
                    add_on = Menu_add_on_items.objects.get(id=id)
                except Menu_add_on_items.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_ADD_ON_ID, error=ErrorConst.INVALID_ADD_ON_ID, status_code=status.HTTP_400_BAD_REQUEST)
                serializer = MenuAddOnItemsSerializer(add_on)
                return json_response(success=True, result=serializer.data, status_code=status.HTTP_200_OK)
            else:
                return json_response(success=False, message=ErrorConst.ADD_ON_REQUIRED, )
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Fully update an add-on item",
        manual_parameters=[openapi.Parameter('id', openapi.IN_PATH, description="Add-on ID", type=openapi.TYPE_STRING, required=True)],
        request_body=MenuAddOnItemsSerializer,
        responses={
            200: openapi.Response("Add-on updated successfully", MenuAddOnItemsSerializer),
            400: "Invalid data or conflict",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )      
    def put(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   add_on= Menu_add_on_items.objects.get(id=id)
                except Menu_add_on_items.DoesNotExist:
                   return json_response(success=False, message=ErrorConst.INVALID_ADD_ON_ID, error=ErrorConst.INVALID_ADD_ON_ID, status_code=status.HTTP_400_BAD_REQUEST)
                
                data=request.data
                name= data.get("name",None)
                menu_items= data.get("menu_items_id", None)
                price= data.get("price", None)
                statusField= data.get("status", None)
                required_fields= {
                    "Name": name,
                    "Item Id" : menu_items,
                    "Price" : price,
                }
                if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
                    return validation_response
                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                
                if Menu_add_on_items.objects.filter(name=name, menu_items=menu_items).exclude(id=add_on.id).exists():
                    return json_response(success=False, message=ErrorConst.ADD_ON_EXISTS, error=ErrorConst.ADD_ON_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                if not Menu_items.objects.filter(id=menu_items).exists():
                        return json_response(success=False, message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                add_on_data={
                    "name" : name,
                    "menu_items" : menu_items,
                    "price" : price,
                    "status" : statusField
                }
                add_on_data= {i:j for i,j in add_on_data.items() if j is not None}
                serializer= MenuAddOnItemsSerializer(add_on, data=add_on_data)
                if serializer.is_valid():
                    add_on= serializer.save()
                    response_data= {
                        "id" : add_on.id,
                        "name" : add_on.name,
                        "price" : add_on.price,
                        "menu_items" : add_on.menu_items_id,
                        "status" : add_on.status,
                        "created_at" : add_on.created_at,
                        "updated_at" : add_on.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ADD_ON_UPDATED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Partially update an add-on item",
        manual_parameters=[openapi.Parameter('id', openapi.IN_PATH, description="Add-on ID", type=openapi.TYPE_STRING, required=True)],
        request_body=MenuAddOnItemsSerializer,
        responses={
            200: openapi.Response("Add-on updated", MenuAddOnItemsSerializer),
            400: "Invalid data or conflict",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def patch(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   add_on= Menu_add_on_items.objects.get(id=id)
                except Menu_add_on_items.DoesNotExist:
                   return json_response(success=False, message=ErrorConst.INVALID_ADD_ON_ID, error=ErrorConst.INVALID_ADD_ON_ID, status_code=status.HTTP_400_BAD_REQUEST)
                data=request.data
                name= data.get("name",None)
                menu_items= data.get("menu_items_id", None)
                price= data.get("price", None)
                statusField= data.get("status", None)

                if statusField:
                    if not CheckValidations.validate_status(statusField):
                        return json_response(success=False, result={}, message=ErrorConst.INVALID_STATUS, error=ErrorConst.INVALID_STATUS, status_code=status.HTTP_400_BAD_REQUEST)    
                
                if (name and not menu_items) or (menu_items and not name):
                    return json_response(success=False, message=ErrorConst.NEED_BOTH_NAME_ITEM_ID, error=ErrorConst.NEED_BOTH_NAME_ITEM_ID, status_code=status.HTTP_400_BAD_REQUEST)               
                elif(name and menu_items):
                    if Menu_add_on_items.objects.filter(name=name, menu_items=menu_items).exclude(id=add_on.id).exists():
                        return json_response(success=False, message=ErrorConst.ADD_ON_EXISTS, error=ErrorConst.ADD_ON_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
                
                    if not Menu_items.objects.filter(id=menu_items).exists():
                        return json_response(success=False, message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

                add_on_data={
                    "name" : name,
                    "menu_items" : menu_items,
                    "price" : price,
                    "status" : statusField
                }
                add_on_data= {i:j for i,j in add_on_data.items() if j is not None}
                serializer= MenuAddOnItemsSerializer(add_on, data=add_on_data, partial=True)
                if serializer.is_valid():
                    add_on= serializer.save()
                    response_data= {
                        "id" : add_on.id,
                        "name" : add_on.name,
                        "price" : add_on.price,
                        "menu_items" : add_on.menu_items_id,
                        "status" : add_on.status,
                        "created_at" : add_on.created_at,
                        "updated_at" : add_on.updated_at
                    }
                    return json_response(success=True, message=ErrorConst.ADD_ON_UPDATED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Delete an add-on item",
        manual_parameters=[openapi.Parameter('id', openapi.IN_PATH, description="Add-on ID", type=openapi.TYPE_STRING, required=True)],
        responses={
            200: "Add-on deleted successfully",
            400: "Invalid ID",
            500: "Internal Server Error"
        },
        tags=["Restaurant"]
    )
    def delete(self,request,id=None):
        try:
            with transaction.atomic():
                try:
                   add_on = Menu_add_on_items.objects.get(id=id)
                except Menu_add_on_items.DoesNotExist:
                    return json_response(success=False, message=ErrorConst.INVALID_ADD_ON_ID, error=ErrorConst.INVALID_ADD_ON_ID, status_code=status.HTTP_400_BAD_REQUEST)
                add_on.delete()
                return json_response(success=True, message=ErrorConst.ADD_ON_DELETED,status_code=status.HTTP_200_OK)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddToCartView(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes=[]
    
    @swagger_auto_schema(
        operation_description="Retrieve cart details based on user or cart code (for anonymous users).",
        manual_parameters=[
            openapi.Parameter(
                'cart_code',
                openapi.IN_QUERY,
                description="Cart code for anonymous users",
                type=openapi.TYPE_STRING
            )
        ],
        responses={
            200: openapi.Response("Cart data", CartSerializer),
            400: "Invalid or missing cart code",
            500: "Internal Server Error"
        },
        tags=["Cart"]
    )
    def get(self,request):
        cart_code= request.query_param.get("cart_code", None)
        if request.user.is_authenticated:
            user= request.user
            try:
                cart= Cart.objects.get(user= user, cart_code=cart_code)
            except Exception as e:
                return json_response(success=False, message=ErrorConst.CART_DOESNT_EXISTS, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)
        else:
            if cart_code:
                try:
                    cart= Cart.objects.get(cart_code= cart_code, user__isnull=True)
                except Exception as e:
                    return json_response(success=False, message=ErrorConst.INVALID_CART_CODE, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)
            else:
                return json_response(success=False, message=ErrorConst.CART_CODE_REQUIRED, error=ErrorConst.CART_CODE_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)        
        cartitems= CartSerializer(cart)
        return json_response(success=True, result=cartitems.data, status_code=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Add an item to the cart (user or guest).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["item_id"],
            properties={
                "item_id": openapi.Schema(type=openapi.TYPE_INTEGER, description="ID of the item to add"),
                "quantity": openapi.Schema(type=openapi.TYPE_INTEGER, description="Quantity of the item", default=1),
                "cart_code": openapi.Schema(type=openapi.TYPE_STRING, description="Cart code for guest users"),
            }
        ),
        responses={
            200: openapi.Response("Item added to cart", CartSerializer),
            400: "Invalid item or quantity",
            500: "Internal Server Error"
        },
        tags=["Cart"]
    )
    def post(self, request):
        item_id = request.data.get("item_id", None)
        if item_id is None:
            return json_response(success=False, message=ErrorConst.ITEM_ID_REQUIRED,error=ErrorConst.ITEM_ID_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            quantity = int(request.data.get("quantity", 1))
            if quantity < 0:  
                return json_response(success=False, message=ErrorConst.INVALID_QUANTITY, error=ErrorConst.INVALID_QUANTITY, status_code=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError) as e:
            return json_response(success=False, message=ErrorConst.INVALID_QUANTITY, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)  
        
        cart_code = request.data.get("cart_code")
        
        try:
            item = Menu_items.objects.get(id=item_id)
        except Menu_items.DoesNotExist:
            return json_response(success=False,message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)

        if request.user.is_authenticated:
            cart, _ = Cart.objects.get_or_create(user=request.user)

        # Case 2: Anonymous User – Use cart_code
        else:
            if cart_code:
                cart = Cart.objects.filter(cart_code=cart_code, user__isnull=True).first()
                if not cart:
                    return json_response(success=False,message=ErrorConst.INVALID_CART_CODE, error=ErrorConst.INVALID_CART_CODE, status_code=status.HTTP_400_BAD_REQUEST)
            else:
                cart = Cart.objects.create()

        # Add or update item
        cart_item, created = CartItem.objects.get_or_create(cart=cart, item=item)
        if not created:
            cart_item.quantity += quantity
        else:
            cart_item.quantity = quantity
        cart_item.save()
        cart_serializer= CartSerializer(cart)
      
        return json_response(success=True, message=ErrorConst.ITEM_ADDED_TO_CART, result=cart_serializer.data, status_code=status.HTTP_200_OK)

class UpdateCartView(APIView):
    authentication_classes= [CustomTokenAuthentication]
    
    @swagger_auto_schema(
        operation_description="Update the quantity of a cart item. Quantity `0` will remove the item.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["item_id", "quantity", "cart_code"],
            properties={
                "item_id": openapi.Schema(type=openapi.TYPE_INTEGER, description="ID of the item"),
                "quantity": openapi.Schema(type=openapi.TYPE_INTEGER, description="New quantity (0 to remove item)"),
                "cart_code": openapi.Schema(type=openapi.TYPE_STRING, description="Cart code for guest users")
            }
        ),
        responses={
            200: openapi.Response("Cart updated", CartSerializer),
            400: "Invalid input or item/cart not found",
            500: "Internal Server Error"
        },
        tags=["Cart"]
    )
    def put(self, request):
        item_id = request.data.get("item_id", None)
        raw_quantity = request.data.get("quantity",None)
        cart_code = request.data.get("cart_code", None)

        required_fields= {
            "Item Id" : item_id,
            "Quantity" : raw_quantity,
            "Cart Code" : cart_code
        }
        if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
            return validation_response
        try:
            quantity = int(raw_quantity)
            if quantity < 0:  
                return json_response(success=False, message=ErrorConst.INVALID_QUANTITY, error=ErrorConst.INVALID_QUANTITY, status_code=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError) as e:
            return json_response(success=False, message=ErrorConst.INVALID_QUANTITY, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)  
   
        try:
            item = Menu_items.objects.get(id=item_id)
        except Menu_items.DoesNotExist:
            return json_response(success=False,message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
        user=None
        if request.user.is_authenticated:
            cart, _ = Cart.objects.get_or_create(user=request.user)
            user= request.user
        # Case 2: Anonymous User – Use cart_code
        else:
            cart = Cart.objects.filter(cart_code=cart_code, user__isnull=True).first()
            if not cart:
                return json_response(success=False,message=ErrorConst.INVALID_CART_CODE, error=ErrorConst.INVALID_CART_CODE, status_code=status.HTTP_400_BAD_REQUEST)
        # user = request.user if request.user.is_authenticated else None
        # user=request.user, when getting cartobject but for that authentication need to be applied
        try:
            cart_item= CartItem.objects.get(cart=cart, item= item)
        except CartItem.DoesNotExist:
            return json_response(success=False, message=ErrorConst.ITEM_NOT_IN_CART, error=ErrorConst.ITEM_NOT_IN_CART, status_code=status.HTTP_400_BAD_REQUEST)    

        if quantity==0:
            cart_item.delete()
        else:    
            cart_item.quantity = quantity
            cart_item.save()
        cart_serializer= CartSerializer(cart)
        return json_response(success=True, message=ErrorConst.CART_UPDATED, result=cart_serializer.data, status_code=status.HTTP_200_OK)

class RemoveCartItem(APIView):
    authentication_classes = [CustomTokenAuthentication]

    @swagger_auto_schema(
        operation_description="Remove an item from the cart using item ID and cart code in request body.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["cart_code"],
            properties={
                "cart_code": openapi.Schema(type=openapi.TYPE_STRING, description="Cart code for guest user carts")
            }
        ),
        manual_parameters=[
            openapi.Parameter(
                'item_id',
                openapi.IN_PATH,
                description="ID of the item to remove from cart",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: openapi.Response("Item deleted successfully from the cart."),
            400: openapi.Response("Bad request or missing data."),
            404: openapi.Response("Item or Cart not found."),
            500: openapi.Response("Internal server error.")
        },
        tags=["Cart"]
    )
    def delete(self,request,item_id):
        cart_code= request.data.get("cart_code", None)
        if request.user.is_authenticated:
            user= request.user
            try:
                cart= Cart.objects.get(user= user, cart_code=cart_code)
            except Cart.DoesNotExist as e:
                return json_response(success=False, message=ErrorConst.CART_DOESNT_EXISTS, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)
        else:
            if cart_code:
                try:
                    cart= Cart.objects.get(cart_code= cart_code, user__isnull=True)
                except Cart.DoesNotExist as e:
                    return json_response(success=False, message=ErrorConst.INVALID_CART_CODE, error=str(e), status_code=status.HTTP_400_BAD_REQUEST)
            else:
                return json_response(success=False, message=ErrorConst.CART_CODE_REQUIRED, error=ErrorConst.CART_CODE_REQUIRED, status_code=status.HTTP_400_BAD_REQUEST)        
        try:
            item = Menu_items.objects.get(id=item_id)
        except Menu_items.DoesNotExist:
            return json_response(success=False,message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            cart_item= CartItem.objects.get(item=item, cart=cart)
        except CartItem.DoesNotExist:
            return json_response(success=False,message=ErrorConst.ITEM_DOESNT_EXISTS, error=ErrorConst.ITEM_DOESNT_EXISTS, status_code=status.HTTP_400_BAD_REQUEST)
        cart_item.delete()
        return json_response(success=True, message= ErrorConst.ITEM_DELETED_FROM_CART, status_code=status.HTTP_200_OK)                

class OrderView(APIView):
    authentication_classes= [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated] 

    @swagger_auto_schema(
        operation_summary="Place an Order",
        operation_description="Creates a new order for the authenticated user from the provided cart_code. Items in the cart will be recorded into the order.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["cart_code"],
            properties={
                "cart_code": openapi.Schema(type=openapi.TYPE_STRING, description="Cart code associated with the user's cart")
            }
        ),
        responses={
            201: openapi.Response(
                description="Order successfully created",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Order saved successfully",
                        "result": {
                            "Order ID": "ORD123456",
                            "Items": [
                                {
                                    "Item Name": "Margherita Pizza",
                                    "Price": 249.0,
                                    "Quantity": 2
                                }
                            ]
                        }
                    }
                }
            ),
            400: openapi.Response(description="Invalid cart code or missing/invalid data"),
            401: openapi.Response(description="Authentication required"),
            500: openapi.Response(description="Internal server error")
        },
        tags=["Order"]
    ) 
    def post(self, request):
        cart_code= request.data.get("cart_code",None)
        required_fields={
            "Cart Id" : cart_code
        }
        
        if (validation_response := CheckValidations.check_missing_fields(required_fields=required_fields)):
            return validation_response
        try:    
            cart_object= Cart.objects.get(cart_code=cart_code, user=request.user)
        except Cart.DoesNotExist:
            return json_response(success=False, message=ErrorConst.INVALID_CART_CODE, error=ErrorConst.INVALID_CART_CODE, status_code=status.HTTP_400_BAD_REQUEST)    

        cart_items_object= CartItem.objects.filter(cart=cart_object)
        if not cart_items_object.exists():
            return json_response(success=False, message=ErrorConst.CART_EMPTY, error=ErrorConst.CART_EMPTY, status_code=status.HTTP_400_BAD_REQUEST)
        order_data= {
            "user" : request.user.id
        }
        order_serializer= OrderSerializer(data=order_data)
        if order_serializer.is_valid():
            order_instance= order_serializer.save()
        else:
            return json_response(success=False, message=ErrorConst.INVALID_DATA, error=order_serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        items_data= []
        for i in cart_items_object:
            order_item_data={
                "order_id" : order_instance.id,
                "item_name" : i.item.name,
                "price" :  i.item.price,
                "quantity" : i.quantity
            }
            order_item_serializer=OrderItemsSerializer(data=order_item_data)
            if order_item_serializer.is_valid():
               order_item_serializer.save()
            else:
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=order_item_serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
            items_data.append({
                "Item Name" :  i.item.name,
                "Price" : i.item.price,
                "Quantity" : i.quantity
            })
        order_response_data={
            "Order ID" : order_instance.order_no,
            "Items" : items_data
        }
        return json_response(success=True, message=ErrorConst.ORDER_SAVED, result=order_response_data, status_code=status.HTTP_201_CREATED)


                


        