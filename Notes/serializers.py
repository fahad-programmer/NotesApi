from rest_framework import serializers
from .models import Note, UserActions
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, update_session_auth_hash

User = get_user_model()

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'title', 'body', 'created_at', 'updated_at']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    

class UserActionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActions
        fields = ('id', 'user', 'action', 'created_at')

class PasswordUpdateSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect old password")
        return value

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
    

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

from rest_framework import serializers

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)
    confirm_password = serializers.CharField(max_length=128)
    pin = serializers.CharField(max_length=6)
    email = serializers.EmailField()

