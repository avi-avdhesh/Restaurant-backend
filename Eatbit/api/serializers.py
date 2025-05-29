from rest_framework import serializers
from .models import UserModel, UserDevice, UserSession, Otp

class UserSerializer(serializers.ModelSerializer):
    password= serializers.CharField(write_only=True)
    class Meta:
        model= UserModel
        fields= ["id","name","email","phone_no","password","country_code","role","created_at","updated_at"]
        read_only_fields=["created_at","updated_at"]

    def create(self, validated_data):
        return UserModel.objects.create_user(**validated_data)

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model= UserModel
        fields= ["name","email","phone_no","country_code","role"]        

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model= UserDevice
        fields= ["id","user_id","device_id","device_token","device_type","os","created_at","updated_at"]
        read_only_fields=["created_at","updated_at"]

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model= UserSession
        fields= ["id","user_id","device_id","token_type","access_token","refresh_token","created_at","updated_at"]
        read_only_fields=["created_at","updated_at"]

class OtpSerializer(serializers.ModelSerializer):
    class Meta:
        model= Otp
        fields= ["id","user_id","otp","expiry_time","created_at","updated_at"]
        read_only_fields= ["created_at","updated_at"]   