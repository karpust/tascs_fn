"""
URL configuration for tasks_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from authapp.views import UserViewSet, GroupViewSet, RegisterAPIView, LoginAPIView
from tasks.views import TaskViewSet, CategoryViewSet, TagViewSet, CommentViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)  # for ViewSets
router.register(r'groups', GroupViewSet)
router.register(r'tasks', TaskViewSet)
router.register(r'categories', CategoryViewSet)
router.register(r'tags', TagViewSet)
# router.register(r"comments", CommentViewSet)  # , basename="task-comments"

# Вложенный роутер:
from rest_framework_nested import routers
comments_router = routers.NestedDefaultRouter(router, r'tasks', lookup='task')
comments_router.register(r'comments', CommentViewSet, basename='task-comments')


urlpatterns = [
    # path('admin/', admin.site.urls),
    path('', include(router.urls)),
    path('api/auth/', include('authapp.urls')),
    path('', include(comments_router.urls)),
    # path('tasks/', include('tasks.urls')),

]


