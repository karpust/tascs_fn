from django.contrib.auth.models import Group, User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from rest_framework import serializers
from django.core.exceptions import ValidationError
from rest_framework.validators import UniqueValidator


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']


class RegisterSerializer(serializers.ModelSerializer):
    # полностью переопределить поле:
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        # изменить поле:
        extra_kwargs = {
            'password': {
                'write_only': True,
            },
            'username': {
                'min_length': 3,
                'max_length': 30,
            }
        }

    def validate_password(self, value):
        # применяет все валидаторы, зарегистрированные в AUTH_PASSWORD_VALIDATORS
        # нет доп логики, можно было validators=[validate_password]
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def create(self, validated_data):
        # вызывается при создании нового пользователя(POST-запрос в API).
        # принимает данные, которые были автоматически проверены ModelSerializer
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],  # автоматом хешируется при create_user
            is_active=False  # user is not active before confirm email
        )
        return user


class ChangePasswordSerializer(serializers.Serializer):

    new_password = serializers.CharField(required=True, write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError({"new_password": "Пароли не совпадают."})
        return data


