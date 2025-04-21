from rest_framework import permissions
from tasks.models import Task


class RolePermission(permissions.BasePermission):
    """Базовый класс разрешений на основе роли пользователя."""
    allowed_roles = []

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in self.allowed_roles
        # return request.user.role in self.allowed_roles  # here i use get_user_role from authapp/apps.py


class IsAdminUser(RolePermission):
    """Разрешение для админов (полный доступ)"""
    allowed_roles = ['Admin']


class IsManagerUser(RolePermission):
    """Разрешение для менеджеров (создание и назначение задач)"""
    allowed_roles = ['Manager']


class TaskPermission(permissions.BasePermission):
    """Объединённое разрешение для работы с задачами."""

    def has_permission(self, request, view):
        # доступ к api /tasks/:
        if request.user.is_authenticated:
            if request.method == "POST":
                return request.user.role in ["manager", "admin"]
            return True
        return False

    def has_object_permission(self, request, view, obj):

        if not request.user.is_authenticated:
            return False

        if request.user.role == 'admin':
            return True

        if request.user.role == 'manager':
            if request.user == obj.owner:
                return request.method in ["GET", 'PATCH', 'PUT']
            return request.method == "GET"

        if request.user.role == 'user':
            # может изменять только поле 'status':
            if obj.executor.contains(request.user):  # m2m
                # same as request.user == obj.executor.filter(id=request.user.id).first()
                # юзер может изменять только те задачи, где назначен исполнителем:
                return request.method == 'PATCH' and set(request.data.keys()).issubset({'status', 'comments'}) or request.method == 'GET'
            return request.method == "GET"


"""
получает поля из request.data(из тела запроса на изменение)
преобразует их во множество
проверяет является ли это множество подмножеством {'status', 'comments'- убери}
"""

class CommentPermission(permissions.BasePermission):
    """проверяет действия ролей, не аутентификацию"""
    def has_permission(self, request, view):

        if not request.user.is_authenticated:
            return False

        if request.method == "POST":
            # try to get task's creator or executor:
            # invalid data - no access:
            task_id = view.kwargs.get('task_pk')  # получаем task_pk из URL
            if not task_id:  # invalid data
                return False
            # from tasks.models import Task  # Импорт здесь, чтобы избежать циклов
            try:
                task = Task.objects.get(id=task_id)
                view.task = task
            except (ValueError, Task.DoesNotExist):
                return False

            return request.user in task.executor.all() or request.user == task.owner
        return True

    def has_object_permission(self, request, view, obj):

        if not request.user.is_authenticated:
            return False

        if request.user.role == "admin":
            return request.method in ["GET", 'DELETE']

        if request.method in ("PUT", "PATCH", "DELETE"):
            return request.user == obj.author
        return True






