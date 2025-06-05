from django.shortcuts import render
from .models import UserModel, UserSession, UserDevice, Otp, Menu_category, Menu_sub_category, Menu_items, Menu_add_on_items
from .serializers import UserSerializer, DeviceSerializer, SessionSerializer, UserUpdateSerializer, OtpSerializer, MenuCategorySerializer, MenuSubCategorySerializer, MenuItemSerializer, MenuAddOnItemsSerializer
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
# from uuid import UUID



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

class ForgetPassword(APIView):
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

class MenuCategory(APIView):
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
      
class MenuSubCategory(APIView):
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
                    return json_response(success=True, message=ErrorConst.CATEGORY_SAVED, result=response_data, status_code=status.HTTP_201_CREATED)
                return json_response(success=False, message=ErrorConst.INVALID_DATA, error=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return json_response(success=False, message=ErrorConst.INTERNAL_SERVER_ERROR, error= str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

               
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


class MenuItems(APIView):
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
