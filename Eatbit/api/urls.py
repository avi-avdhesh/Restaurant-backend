from django.urls import path
from .views import RegisterUser, UpdateUser, DeleteUser, UserLogOut, LoginView, ForgetPassword, OtpVerify, ResetPassword, ChangePassword, MenuCategory, MenuSubCategory
import uuid

urlpatterns=[
    path('register/', RegisterUser.as_view()),
    path('update-user/', UpdateUser.as_view()),
    path('delete-user/', DeleteUser.as_view()),
    path('logout', UserLogOut.as_view()),
    path('login/', LoginView.as_view()),
    path('password/forgot/', ForgetPassword.as_view()),
    path('password/verify/', OtpVerify.as_view()),
    path('password/reset/', ResetPassword.as_view()),
    path('password/change/', ChangePassword.as_view()),
    path('restaurant/category/',MenuCategory.as_view()),
    path('restaurant/category/<uuid:id>/',MenuCategory.as_view()),
    path('restaurant/sub-category/',MenuSubCategory.as_view()),
    path('restaurant/sub-category/<uuid:id>/',MenuSubCategory.as_view())
]