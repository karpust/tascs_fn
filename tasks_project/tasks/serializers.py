from django.contrib.auth import get_user_model
from django.db.models.fields import CharField
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
    tags = serializers.ListField(child=serializers.CharField(), write_only=True, required=False) # m2m - передаю сериализатору список строк
    tag_names = serializers.SerializerMethodField(read_only=True)  # get_tag_names
    category = serializers.CharField(required=False)

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'status', 'deadline', 'priority', 'owner', 'executor','category', 'tags', 'tag_names']

    def get_tag_names(self, obj):
        return [tag.name for tag in obj.tags.all()]

    def create_or_get_category(self, category_name):
        category_name = category_name.strip()  # убираю пробелы, исключая дублирование
        category, _ = Category.objects.get_or_create(name=category_name)
        return category

    def create_or_get_tags(self, tag_names):
        """return list of tag objects"""
        tags = []
        for tag_name in tag_names:
            tag_name = tag_name.strip()
            tag, _ = Tag.objects.get_or_create(name=tag_name)
            tags.append(tag)
        return tags

    def create(self, validated_data):
        category_data = validated_data.pop("category", None)
        tags_data = validated_data.pop("tags", [])
        executor = validated_data.pop("executor")

        category = self.create_or_get_category(category_data) if category_data else None
        tags = self.create_or_get_tags(tags_data)

        task = Task.objects.create(category=category, **validated_data)
        task.executor.set(executor)
        task.tags.set(tags)
        return task

    def update(self, instance, validated_data):
        category_data = validated_data.pop("category", None)
        tags_data = validated_data.pop("tags", [])
        validated_data.pop("owner", None) # not change owner if update

        if category_data:
            category = self.create_or_get_category(category_data)
            instance.category = category

        if tags_data:
            tags = self.create_or_get_tags(tags_data)
            instance.tags.set(tags)
        # update remaining fields:
        # for attr, value in validated_data.items():
        #     setattr(instance, attr, value)
        # instance.save()
        # return instance
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        rep = super(TaskSerializer, self).to_representation(instance)
        if instance.category:
            rep["category"] = instance.category.name
        rep["tags"] = [tag.name for tag in instance.tags.all()]
        return rep


class CommentSerializer(serializers.ModelSerializer):
    author = serializers.HiddenField(default=serializers.CurrentUserDefault())
    # заполняю автоматически и скрываю поля author, task

    # поле скрыто из входных данных (`HiddenField`)
    # исключает возможность подмены владельца.
    # текущий пользователь автоматически берется из запроса(request.user).
    # работает только если сериализатор используется в представлении, где передаётся request.
    # не требует ручного назначения в `create()`

    class Meta:
        model = Comment
        fields = ["id", "task", "author", "text", "created_at"]
        read_only_fields = ["task", "created_at"]