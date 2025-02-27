from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from .models import User, Referral
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'referral_code', 'referred_by', 'reward_points']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid email format.")
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate_referral_code(self, value):
        if value and not User.objects.filter(referral_code=value).exists():
            raise serializers.ValidationError("Invalid referral code.")
        return value

    def create(self, validated_data):
        # Hash the password before saving the user
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

class ReferralSerializer(serializers.ModelSerializer):
    class Meta:
        model = Referral
        fields = ['referrer', 'referred_user', 'date_referred', 'status']