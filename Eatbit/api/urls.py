from django.urls import path
from .views import RegisterUser, UpdateUser, DeleteUser, UserLogOut, LoginView, ForgetPassword, OtpVerify, ResetPassword, ChangePassword, MenuCategory, MenuSubCategory, MenuItems, MenuAddOnItem, AddToCartView, RemoveCartItem, UpdateCartView,OrderView, ListUsersView, RetrieveUserView , MenuCategoryAdd, MenuCategoryList,MenuSubCategoryAdd, MenuSubCategoryList, MenuItemAdd, MenuItemsList, MenuAddOnItemAdd, MenuAddOnItemList
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
    path('restaurant/category/',MenuCategoryAdd.as_view()),
    path('restaurant/category-list/',MenuCategoryList.as_view()),
    path('restaurant/category/<uuid:id>/',MenuCategory.as_view()),
    path('restaurant/sub-category/',MenuSubCategoryAdd.as_view()),
    path('restaurant/sub-category-list/',MenuSubCategoryList.as_view()),   
    path('restaurant/sub-category/<uuid:id>/',MenuSubCategory.as_view()),
    path('restaurant/item-add/', MenuItemAdd.as_view()),
    path('restaurant/items-list/', MenuItemsList.as_view()),
    path('restaurant/item/<uuid:id>/',MenuItems.as_view()),
    path('restaurant/addon/', MenuAddOnItemAdd.as_view()),
    path('restaurant/addon-list/', MenuAddOnItemList.as_view()),
    path('restaurant/addon/<uuid:id>/', MenuAddOnItem.as_view()),
    path('user/addtocart/',AddToCartView.as_view()),
    path('user/removefromcart/<uuid:item_id>/', RemoveCartItem.as_view()),
    path('user/updatecart/', UpdateCartView.as_view()),
    path('order/', OrderView.as_view()),
    path('userslist', ListUsersView.as_view()),
    path('user-profile', RetrieveUserView.as_view())
]