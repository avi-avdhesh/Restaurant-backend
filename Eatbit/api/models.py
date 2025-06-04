from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid

# Create your models here.
class Role(models.TextChoices):
    USER = 'user', 'User'
    ADMIN = 'admin', 'Admin'

class Status(models.TextChoices):
    INACTIVE = 'inactive', 'Inactive'
    ACTIVE = 'active', 'Active'

class DeviceType(models.TextChoices):
    MOBILE = 'mobile', 'Mobile'
    TABLET = 'tablet', 'Tablet'
    DESKTOP = 'desktop', 'Desktop'

class OS(models.TextChoices):
    ANDROID = 'android', 'Android'
    IOS = 'ios', 'iOS'
    WINDOWS = 'windows', 'Windows'
    MACOS = 'macos', 'macOS'

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email Field is required")
        email= self.normalize_email(email)
        user= self.model(email= email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class UserModel(AbstractBaseUser):

    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  
    name= models.CharField(max_length= 120)
    email= models.EmailField(max_length=225, unique=True)
    password= models.CharField(max_length= 225)
    phone_no= models.CharField(max_length= 225)
    country_code= models.CharField(max_length= 225)
    role= models.CharField(choices=Role.choices, default=Role.USER)
    status= models.CharField(choices=Status.choices, default=Status.ACTIVE)
    created_at= models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at= models.DateTimeField(auto_now= True, blank=True, null=True)
    deleted_at= models.DateTimeField(blank=True, null=True)

    objects= CustomUserManager()
    USERNAME_FIELD= 'email'
    REQUIRED_FIELDS= ['name','phone_no','password']

    class Meta:
        db_table='users'
        ordering= ['-created_at']

    def __str__(self):
        return self.email

class UserDevice(models.Model):

    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id= models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="device", db_column="user_id")
    device_id= models.CharField(max_length=255)
    device_token= models.CharField(max_length=255, blank=True, null=True)
    device_type= models.CharField(choices=DeviceType.choices)
    os = models.CharField(choices= OS.choices)
    created_at= models.DateTimeField(auto_now_add= True)
    updated_at= models.DateTimeField(auto_now= True, blank=True, null=True)
    deleted_at= models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table= "user_devices"
        ordering= ['-created_at']

class UserSession(models.Model):

    class TokenType(models.IntegerChoices):
        TOKEN_ACCESS = 0, 'Access_token'
        TOKEN_REFRESH = 1,  'Refresh_token'

    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id= models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="session", db_column="user_id")
    device_id = models.ForeignKey(UserDevice, on_delete=models.CASCADE, related_name= "session", db_column="device_id")
    token_type = models.IntegerField(choices=TokenType.choices, default=TokenType.TOKEN_ACCESS)
    access_token= models.CharField(max_length=500)
    refresh_token= models.CharField(max_length=500)
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table= "user_sessions"
        ordering= ['-created_at']
   
class Otp(models.Model):
    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id= models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="otp", db_column="user_id")
    otp= models.CharField(max_length=10)
    expiry_time= models.DateTimeField()
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)
    # otp_type?
    class Meta:
        db_table="otp"
        ordering=['created_at']


class Menu_category(models.Model):
    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name= models.CharField(max_length=225, default="default")
    status= models.CharField(choices=Status.choices, default=Status.ACTIVE)
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)

class Menu_sub_category(models.Model):
    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    category_id= models.ForeignKey(Menu_category, on_delete=models.CASCADE, related_name="menu_sub_category", db_column="category_id")
    name= models.CharField(max_length=225, default="default")
    status= models.CharField(choices=Status.choices, default=Status.ACTIVE)
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)

class Menu_items(models.Model):
    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name= models.CharField(max_length=225, default="default")
    desc= models.CharField(max_length=225)
    image_url = models.URLField(max_length=500)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    category_id= models.ForeignKey(Menu_category, on_delete=models.CASCADE, related_name="menu_items", db_column="category_id")
    sub_category_id= models.ForeignKey(Menu_sub_category, on_delete=models.CASCADE,related_name="menu_items", db_column="sub_category_id")     
    status= models.CharField(choices=Status.choices, default=Status.ACTIVE)
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)

class Menu_add_on_items(models.Model):
    id= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name= models.CharField(max_length=225, default="default")
    menu_items= models.ForeignKey(Menu_items, on_delete=models.CASCADE, related_name="menu_add_on_items", db_column="menu_items_id")
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    status= models.CharField(choices=Status.choices, default=Status.ACTIVE)
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)
    deleted_at= models.DateTimeField(null=True, blank=True)



    
    

    

    


