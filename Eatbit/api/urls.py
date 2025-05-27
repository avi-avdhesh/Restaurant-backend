from django.urls import path
from .views import RegisterUser, UpdateUser, DeleteUser, UserLogOut, LoginView

urlpatterns=[
    path('register/', RegisterUser.as_view()),
    path('update-user/', UpdateUser.as_view()),
    path('delete-user/', DeleteUser.as_view()),
    path('logout', UserLogOut.as_view()),
    path('login/', LoginView.as_view())
]