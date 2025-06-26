from rest_framework import serializers
from .models import UserModel, UserDevice, UserSession, Otp, Menu_category, Menu_sub_category, Menu_items, Menu_add_on_items, Cart, CartItem, Order, OrderItems

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

class MenuCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model= Menu_category
        fields=["id","name","status","created_at","updated_at"]
        read_only_fields=["created_at", "updated_at"]

    def update(self, instance, validated_data):
        if 'status' not in validated_data:
            validated_data['status'] = instance.status or Menu_category._meta.get_field('status').default
        return super().update(instance, validated_data)    

class MenuSubCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model= Menu_sub_category
        fields= ["id","name","category_id","status","created_at","updated_at"]
        read_only_fields=["created_at", "updated_at"]

    def update(self, instance, validated_data):
        if 'status' not in validated_data:
            validated_data['status'] = instance.status or Menu_sub_category._meta.get_field('status').default
        return super().update(instance, validated_data)  

class MenuItemSerializer(serializers.ModelSerializer):
    class Meta:
        model= Menu_items
        fields=["id","name","desc","image_url","price","category_id","sub_category_id","status","created_at","updated_at"]
        read_only_fields=["created_at", "updated_at"]

    def update(self, instance, validated_data):
        if 'status' not in validated_data:
            validated_data['status'] = instance.status or Menu_sub_category._meta.get_field('status').default
        return super().update(instance, validated_data)      

class MenuAddOnItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model= Menu_add_on_items
        fields=["id","name","menu_items","price","status","created_at","updated_at"]
        read_only_fields=["created_at", "updated_at"]

    def update(self, instance, validated_data):
        if 'status' not in validated_data:
            validated_data['status'] = instance.status or Menu_sub_category._meta.get_field('status').default
        return super().update(instance, validated_data)     

class CartItemSerializer(serializers.ModelSerializer):

        item = MenuItemSerializer(read_only=True)
        item_id = serializers.PrimaryKeyRelatedField(queryset= Menu_items.objects.all(), write_only= True, source="item")
        cart_id = serializers.PrimaryKeyRelatedField(queryset= Cart.objects.all(), write_only=True, source= "cart")
        sub_total= serializers.SerializerMethodField()

        class Meta:
            model= CartItem
            fields = ["item","quantity","item_id","cart_id","sub_total"]
        
        def get_sub_total(self, cartitem):
            return cartitem.quantity * cartitem.item.price

        
        def validate_quantity(self, value):
            if value <= 0:
                raise serializers.ValidationError("Quantity must be greater than zero.")
            return value    

class CartSerializer(serializers.ModelSerializer):

    cart_items = CartItemSerializer(read_only=True, many=True)
    cart_total = serializers.SerializerMethodField()
    class Meta:
        model = Cart
        fields  =  ["cart_code","cart_items","cart_total","created_at","updated_at"] 
        read_only_fields=["created_at","updated_at"]
        
    def get_cart_total(self, cart):
        total_cart_items= cart.cart_items.all()
        total = sum([item.quantity * item.item.price for item in total_cart_items])
        return total

class OrderItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model =OrderItems
        fields=["order_id","item_name","price","quantity"]
        write_only_fields=["order_id"]

class OrderSerializer(serializers.ModelSerializer):
    # order_items= OrderItemsSerializer(read_only=True, many=True)
    class Meta:
        model= Order
        fields=["id", "order_no","user", "created_at","updated_at"]
        read_only_fields=["order_no", "created_at","updated_at"]       








