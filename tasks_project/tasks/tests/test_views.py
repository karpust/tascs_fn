from datetime import timedelta

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.utils.timezone import now
from rest_framework import status
from rest_framework.test import APITestCase, APIClient, force_authenticate
from rest_framework_simplejwt.tokens import AccessToken
from tasks.models import Task, Category, Tag, Comment

User = get_user_model()

class BaseTestCase(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.category = Category.objects.create(name='Test Category')
        cls.tag = Tag.objects.create(name='Test Tag')
        cls.admin = cls.make_user("admin", "admin")
        cls.manager = cls.make_user('manager', 'manager')
        cls.user = cls.make_user("user", "user")
        cls.executor = cls.make_user("executor", "user")
        cls.owner = cls.make_user('owner', 'manager')
        cls.all_users = [cls.admin, cls.manager, cls.user, cls.executor, cls.owner]

    @classmethod
    def make_user(cls, username, role):
        user = User.objects.create_user(username=username, password="password123")
        user.profile.role = role
        user.profile.save()
        return user

    def make_authenticated(self, user):
        """
        состояние кук (access_token) привязано к тестовому клиенту self.client
        при вызове self.client.get('/api/data/') автоматически передаются все куки,
        которые были установлены ранее для юзера.
        сервер берет куку и получает из ее токена юзера.
        если выполнили self.make_authenticated(admin) в тесте, то теперь
        все запросы через self.client будут аутентифицироваться как admin
        чтобы тестировать разных пользователей в одном тесте, нужно пересоздавать клиент self.client = APIClient()
        или делать перезапись кук - make_authenticated(другой юзер)
        полностью перезаписывает все куки клиента, а не добавляет новые. Это жесткая замена, а не обновление.
        """
        self.access_token = str(AccessToken.for_user(user))

        # запись куки с токеном - это полная перезапись кук а не добавление:
        self.client.cookies.load({
            'access_token': self.access_token,
            # 'refresh_token':
        })
        # добавляю параметры загруженному токену:
        self.client.cookies['access_token']['httponly'] = True
        self.client.cookies['access_token']['samesite'] = 'Lax'

    def make_task(self, owner, executor, title="Task title"):
        task = Task.objects.create(
            title=title,
            deadline=timezone.now() + timedelta(days=1),
            status='To Do',
            priority='Medium',
            owner=owner,
            category=self.category,
        )
        task.executor.set([executor])  # m2m
        task.tags.set([self.tag])  # m2m
        return task


class BaseTaskTestCase(BaseTestCase):

    def setUp(self):
        self.task = self.make_task(self.owner, self.executor)
        self.list_url = reverse('task-list')
        self.url = reverse('task-detail', args=[1])  # '/tasks/1/' # f'/tasks/{self.task.id}/'
        # self.url = reverse('task-detail', kwargs={'pk': self.task.pk})


class TaskListViewTests(BaseTaskTestCase):
    """доступ к api /tasks/ у всех авторизованных"""

    def test_list_as_authenticated(self):
        for user in self.all_users:
            self.make_authenticated(user)  # перезаписываю куки
            response = self.client.get(self.list_url)  # запрос с новыми куками
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_unauthenticated(self):
        self.client = APIClient()  # удаляю куки
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TaskDetailViewTests(BaseTaskTestCase):
    """просматривать задачу могут все авторизованные"""

    def test_detail_as_authenticated(self):
        for user in self.all_users:
            self.make_authenticated(user)  # перезаписываю куки
            response = self.client.get(self.url)  # запрос с новыми куками
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_unauthenticated(self):
        self.client = APIClient()  # удаляю куки
        response = self.client.get(self.url )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TaskCreateViewTests(BaseTaskTestCase):
    """создавать задачу может только админ и менеджер"""

    def setUp(self):
        super().setUp()
        self.valid_data = {
            'title': 'New task',
            'description': 'New Description',
            'status': 'done',
            'priority': 'high',
            'deadline': timezone.now() + timedelta(days=1),
            'executor': [self.executor.id],
        }
        self.invalid_data = {
            'title': 'Invalid task',
            'description': 'New Description',
            'status': 'done',
            'priority': 'high',
            'deadline': timezone.now() + timedelta(days=1),
        }

    def test_create_valid_data(self):
        self.make_authenticated(self.admin)

        response = self.client.post(self.list_url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Task.objects.count(), 2)
        self.assertTrue(Task.objects.filter(title="New task").exists())

    def test_create_invalid_data(self):
        self.make_authenticated(self.admin)

        response = self.client.post(self.list_url, self.invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Task.objects.count(), 1)
        self.assertFalse(Task.objects.filter(title="Invalid task").exists())

    def test_create_task_missing_fields(self):
        self.make_authenticated(self.admin)

        response = self.client.post(self.list_url, {"title": "Task missing fields"}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Task.objects.count(), 1)
        self.assertFalse(Task.objects.filter(title="Task missing fields").exists())

    def test_create_task_owner_add_automatically(self):
        self.make_authenticated(self.admin)

        response = self.client.post(self.list_url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Task.objects.latest('id').owner, self.admin)

    def test_create_as_admin(self):
        self.make_authenticated(self.admin)
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_as_manager(self):
        self.make_authenticated(self.manager)
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_as_user(self):
        self.make_authenticated(self.user)
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_unauthenticated(self):
        self.client = APIClient()
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TaskPutViewTests(BaseTaskTestCase):
    """полностью обновлять задачу может только админ и ее создатель"""

    def setUp(self):
        super().setUp()
        self.valid_data = {
            'title': 'New task',
            'description': 'New Description',
            'status': 'done',
            'priority': 'high',
            'deadline': timezone.now() + timedelta(days=1),
            'executor': [self.executor.id],
        }
        self.invalid_data = {
            'title': 'Invalid task',
            'description': 'New Description',
            'status': 'Super Done',
            'priority': 'high',
            'deadline': timezone.now() + timedelta(days=1),
            'executor': [self.executor.id],
        }

    def test_put_valid_data_as_admin(self):
        self.make_authenticated(self.admin)

        response = self.client.put(self.url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Task.objects.latest('id').owner, self.admin)

    def test_put_invalid_data(self):
        self.make_authenticated(self.admin)
        response = self.client.put(self.url, self.invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_missing_fields(self):
        self.make_authenticated(self.admin)
        response = self.client.put(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_as_owner(self):
        self.make_authenticated(self.owner)

        response = self.client.put(self.url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Task.objects.latest('id').owner, self.owner)

    def test_put_as_forbidden_authenticated(self):
        for user in (self.manager, self.user, self.executor):
            self.make_authenticated(user)
            response = self.client.put(self.url, self.valid_data, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_put_unauthenticated(self):
        self.client = APIClient()
        response = self.client.put(self.url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TaskPatchViewTests(BaseTaskTestCase):
    """частично обновлять задачу могут админ, ее создатель и исполнитель(только поле status)"""

    def setUp(self):
        super().setUp()
        self.valid_data = {'title': 'Patched task'}
        self.invalid_data = {
            'title': 'Invalid task',
            'priority': 'Super High',
        }

    def test_patch_valid_data_as_admin(self):
        self.make_authenticated(self.admin)

        response = self.client.patch(self.url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Task.objects.latest('id').title, 'Patched task')

    def test_patch_invalid_data(self):
        self.make_authenticated(self.admin)

        response = self.client.patch(self.url, self.invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(Task.objects.latest('id').title, 'Patched task')

    def test_patch_not_changed_owner(self):
        self.make_authenticated(self.admin)
        self.assertEqual(self.task.owner, self.owner)

        response = self.client.patch(self.url, {"owner": self.admin.id}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task.refresh_from_db() # обновляю данные объекта task из бд, если они были изменены
        self.assertNotEqual(self.task.owner, self.admin)
        self.assertEqual(self.task.owner, self.owner)

    def test_patch_as_owner(self):
        self.make_authenticated(self.owner)

        response = self.client.patch(self.url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Task.objects.latest('id').owner, self.owner)

    def test_patch_allowed_fields_as_executor(self):
        self.make_authenticated(self.executor)
        data = {"status": "done"}

        response = self.client.patch(self.url, data, format='json', partial=True)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(self.executor, self.task.executor.filter(id=self.executor.id).first())
        self.assertTrue(self.task.executor.contains(self.executor))
        self.assertEqual(Task.objects.latest('id').owner, self.owner)

    def test_patch_forbidden_authenticated_or_not_allowed_fields(self):
        """to executor not allowed change fields except <status>"""
        for user in (self.user, self.executor, self.manager):
            self.make_authenticated(user)
            response = self.client.patch(self.url, self.valid_data, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_patch_unauthenticated(self):
        self.client = APIClient()
        response = self.client.patch(self.url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TaskDeleteViewTests(BaseTaskTestCase):
    """удалять задачу может только админ"""

    def test_delete_as_admin(self):
        self.make_authenticated(self.admin)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_forbidden_authenticated(self):
        for user in (self.user, self.executor, self.manager, self.owner):
            self.make_authenticated(user)
            response = self.client.delete(self.url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_as_unauthorized(self):
        self.client = APIClient()
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class BaseCommentTestCase(BaseTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.author = cls.make_user('author', 'User')
        cls.all_users.append(cls.author)

    def setUp(self):
        self.task = self.make_task(self.owner, self.executor)
        self.comment = self.make_comment(self.task, self.author)
        # self.url = reverse('comment-detail', args=[1])
        # self.list_url = reverse('comment-list')
        # for nested-routers:
        self.url = reverse('task-comments-detail', kwargs={'task_pk': self.task.id, 'pk': self.comment.id})
        self.list_url = reverse('task-comments-list', kwargs={'task_pk': self.task.id})

        self.valid_data = {"text": "New comment text"}
        self.invalid_data = {"text": ""}



    @classmethod
    def make_comment(cls, task, author, text="Comment text"):
        comment = Comment.objects.create(
            task=task,
            author=author,
            text=text,
        )
        return comment


class CommentListViewTests(BaseCommentTestCase):
    """доступ к api /comments/ у всех авторизованных"""

    def test_list_as_authenticated(self):
        for user in self.all_users:
            self.make_authenticated(user)  # создаю куки с токеном юзера
            response = self.client.get(self.list_url)  # запрос с куками юзера
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_unauthenticated(self):
        self.client = APIClient()  # удаляю куки
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CommentDetailViewTests(BaseCommentTestCase):
    """просматривать комментарий могут все авторизованные"""

    def test_detail_as_authenticated(self):
        for user in self.all_users:
            self.make_authenticated(user)
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_unauthenticated(self):
        self.client = APIClient()  # удаляю куки
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CommentCreateViewTests(BaseCommentTestCase):
    """создавать комментарии могут только админ и менеджер"""

    def test_create_comment_valid_data_by_owner(self):
        self.make_authenticated(self.owner)

        response = self.client.post(self.list_url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Comment.objects.count(), 2)
        self.assertTrue(Comment.objects.filter(text="New comment text").exists())

    def test_create_comment_invalid_data(self):
        self.make_authenticated(self.owner)

        response = self.client.post(self.list_url, self.invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Comment.objects.count(), 1)
        self.assertFalse(Comment.objects.filter(text="Invalid comment text").exists())

    def test_create_comment_missing_fields(self):
        self.make_authenticated(self.owner)

        response = self.client.post(self.list_url, {}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Comment.objects.count(), 1)
        self.assertFalse(Comment.objects.filter(text="").exists())

    def test_create_comment_author_add_automatically(self):
        self.make_authenticated(self.owner)

        response = self.client.post(self.list_url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Comment.objects.latest('id').author, self.owner)

    def test_create_comment_by_executor(self):
        self.make_authenticated(self.executor)
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Comment.objects.latest('id').author, self.executor)

    def test_create_as_forbidden_authenticated(self):
        for user in (self.user, self.admin, self.manager):
            self.make_authenticated(user)
            response = self.client.post(self.list_url, self.valid_data)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_unauthenticated(self):
        self.client = APIClient()
        response = self.client.post(self.list_url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CommentPutViewTests(BaseCommentTestCase):
    """полностью обновлять комментарий может только автор"""

    def test_put_valid_data_as_author(self):
        self.make_authenticated(self.author)

        response = self.client.put(self.url, self.valid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Comment.objects.latest('id').author, self.author)

    def test_put_invalid_data(self):
        self.make_authenticated(self.author)
        response = self.client.put(self.url, self.invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_comment_missing_fields(self):
        self.make_authenticated(self.author)

        response = self.client.put(self.url, {}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Comment.objects.filter(text="").exists())

    def test_put_as_forbidden_authenticated(self):
        for user in (self.owner, self.admin, self.manager, self.user):
            self.make_authenticated(user)
            response = self.client.put(self.url, self.valid_data, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_put_as_unauthenticated(self):
        self.client = APIClient()
        response = self.client.put(self.url, self.valid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CommentPatchViewTests(BaseCommentTestCase):
    """частично изменять комментарий может только автор"""

    def test_patch_valid_data_as_author(self):
        self.make_authenticated(self.author)

        response = self.client.patch(self.url, {"text": "New comment Patch text"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Comment.objects.latest('id').text, "New comment Patch text")

    def test_patch_invalid_data(self):
        self.make_authenticated(self.author)
        response = self.client.patch(self.url, {"text": ""})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_comment_as_forbidden_authenticated(self):
        for user in self.all_users:
            if user.username != "author":
                self.make_authenticated(user)
                response = self.client.patch(self.url, {"text": "New comment Patch text"})
                self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_patch_comment_as_unauthenticated(self):
        self.client = APIClient()
        response = self.client.patch(self.url, {"text": "New comment Patch text"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class CommentDeleteViewTests(BaseCommentTestCase):

    def test_delete_as_author(self):
        self.make_authenticated(self.author)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Comment.objects.count(), 0)

    def test_delete_as_admin(self):
        self.make_authenticated(self.admin)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Comment.objects.count(), 0)

    def test_delete_as_forbidden_authenticated(self):
        for user in self.all_users:
            if user.username not in ("author", "admin"):
                self.make_authenticated(user)
                response = self.client.delete(self.url)
                self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_comment_as_unauthenticated(self):
        self.assertEqual(Comment.objects.count(), 1)
        self.client = APIClient()

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(Comment.objects.count(), 1)



