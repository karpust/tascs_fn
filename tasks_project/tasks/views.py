from django.shortcuts import render
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, filters
from rest_framework.generics import get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from tasks.models import Task, Category, Tag, Comment
from tasks.serializers import TaskSerializer, CategorySerializer, TagSerializer, CommentSerializer
from .permissions import TaskPermission, CommentPermission


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [TaskPermission]


class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [CommentPermission]

    def get_queryset(self):
        # фильтрую комментарии по задаче из URL:
        return Comment.objects.filter(task_id=self.kwargs['task_pk'])
        # kwargs-словарь параметров URL, извлечённых из маршрута
        # task_pk-ключ кот исп drf-nested-routers на основе lookup='task' урла
        # поле task — это ForeignKey, а в базе оно хранится как task_id

    def perform_create(self, serializer):
        # автоматически привязываю задачу и автора:
        task = Task.objects.get(id=self.kwargs['task_pk'])
        serializer.save(task=task) # author=self.request.user,


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [TaskPermission]


class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [TaskPermission]
