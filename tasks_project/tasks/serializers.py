from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Task, Category, Tag, Comment


User = get_user_model()


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name']


class TaskSerializer(serializers.ModelSerializer):
    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())
    category = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all(), required=False)
    tags = serializers.SlugRelatedField (queryset=Tag.objects.all(), many=True, slug_field='name', required=False)  # m2m

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'status', 'deadline', 'priority', 'owner', 'executor','category', 'tags']

    # поле owner заполняю автоматически и скрываю используя
    # serializers.HiddenField(default=serializers.CurrentUserDefault())

    # def create(self, validated_data):
    #     # same do 'perform_created' in views.py
    #     # беру текущего юзера, который делает запрос на создание объекта Task
    #     # из контекста запроса и добавляю его в дату на создание объекта:
    #     request = self.context.get('request')
    #     if request and request.user:
    #         validated_data['owner'] = request.user
    #     return super().create(validated_data)

class CommentSerializer(serializers.ModelSerializer):
    # author = serializers.HiddenField(default=serializers.CurrentUserDefault()) делаю во вью
    # заполняю автоматически и скрываю поля author, task

    # поле скрыто из входных данных (`HiddenField`)
    # исключает возможность подмены владельца.
    # текущий пользователь автоматически берется из запроса(request.user).
    # работает только если сериализатор используется в представлении, где передаётся request.
    # не требует ручного назначения в `create()`

    class Meta:
        model = Comment
        fields = ["id", "task", "author", "text", "created_at"]
        read_only_fields = ["task", "author", "created_at"]