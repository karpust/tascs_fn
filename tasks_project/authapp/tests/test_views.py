import re
from datetime import timedelta, datetime
from http.client import responses
from unittest.mock import patch
from urllib import response

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from freezegun import freeze_time

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
# from django.test.utils import freeze_time
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.core.cache import cache, caches
from django.core import mail

from tasks_project import settings
from authapp.utils import create_verification_link, generate_email_verification_token, time_email_verification
from urllib.parse import urlparse

User = get_user_model()


class RegisterAPIViewTest(APITestCase):

    def setUp(self):
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "strongpassword123",
        }
        self.url = reverse('register')  # получаем URL по имени

    def test_register_successfull(self):
        """Тестируем регистрацию пользователя через API."""
        response = self.client.post(self.url, self.user_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("Спасибо за регистрацию", response.data["message"])

        user_exists = User.objects.filter(email=self.user_data["email"]).exists()
        self.assertTrue(user_exists)

        # print(mail.outbox)  # [<django.core.mail.message.EmailMultiAlternatives object at 0x0000013FCB9D9F00>]
        # список, в который попадают все отправленные письма при использовании django.core.mail.send_mail()
        self.assertEqual(len(mail.outbox), 1)  # проверяем, что отправлено 1 письмо
        self.assertIn("Подтверждение email", mail.outbox[0].subject)
        # print(f'mail.outbox[0].body = {mail.outbox[0].body}')
        # print(f'mail.outbox[0].subject = {mail.outbox[0].subject}')
        self.assertIn("confirm_register", mail.outbox[0].body)

        # проверяю что токен сохраняется в кэше:
        # беру тело письма со ссылкой в которой вшит токен:
        email_body = mail.outbox[0].body
        print(f'email_body: {email_body}')
        # нахожу начало, конец токена:
        token_start = email_body.find('token=') + len('token=')
        token_end = email_body.find('&expires_at=')

        # ищу этот токен в кэше потока джанги:
        cache_key = f"email_verification_token_{email_body[token_start:token_end]}"
        print(f'cache_key: {cache_key}')
        cached_token = cache.get(cache_key)
        self.assertIsNotNone(cached_token, cached_token)

    def test_register_missing_fields(self):
        """Тест с отсутствующими обязательными полями"""
        required_fields = ["username", "email", "password"]

        for field in required_fields:
            data = {
                "username": "testuser",
                "email": "test@example.com",
                "password": "strongpassword123",

            }
            data.pop(field)  # Удаляем одно из обязательных полей
            response = self.client.post(self.url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn(field, response.data)  # проверяет, что в ответе API (response.data) присутствует указанный field(JSON-ответ с описанием ошибок)


class ConfirmRegisterAPIViewTest(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="some_user",
            email="<some_user@example.com>",
            password="<some_user_password123>",
            is_active=False,
        )

    def test_user_have_valid_token(self):

        verification_link = create_verification_link(self.user)

        response = self.client.get(verification_link)

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content.decode())
        self.assertIn('Email is successfully confirmed', response.content.decode())

    def test_user_have_invalid_token(self):

        verification_link = create_verification_link(self.user)
        # get valid token and replace with invalid token:
        start_token = verification_link.find("token=") + len("token=")
        end_token = verification_link.find("&expires_at=")
        link_with_invalid_token = f'{verification_link[:start_token]}' + 'some_invalid_token' + f'{verification_link[end_token:]}'

        response = self.client.get(link_with_invalid_token)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('The link has invalid token.', response.content.decode())


    def test_token_expired_or_not_provided(self):
        """если токен уже удален из кэша или не был передан"""

        verification_link = create_verification_link(self.user)
        # remove token form link:
        start_token = verification_link.find("token=")
        end_token = verification_link.find("&expires_at=")
        link_without_token = f'{verification_link[:start_token]} + {verification_link[end_token:]}'

        response = self.client.get(link_without_token)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('The token was expired or not provided', response.content.decode())

    def test_user_already_verified(self):

        self.user.is_active = True
        self.user.save()
        verification_link = create_verification_link(self.user)

        response = self.client.get(verification_link)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
        self.assertIn('Email has already been confirmed', response.content.decode())

    def test_user_not_registered(self):
        verification_link = create_verification_link(self.user)
        self.user.delete()

        with self.assertRaisesMessage(ObjectDoesNotExist, 'The user was not found. Please, repeat the registration.'):
            self.client.get(verification_link)


class RepeatConfirmRegisterAPIViewTest(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="some_user",
            email="some_user@example.com",
            password="some_user_password123",
            is_active=False)

        self.url = reverse("repeat_confirm_register")


    def test_confirm_query_successfull(self):

        user_data = {
            "username": "some_user",
            "password": "some_user_password123",
        }

        response = self.client.post(self.url, user_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content.decode())
        self.assertIn('На ваш email было отправлено письмо-подтверждение', response.content.decode())

    def test_wrong_username(self):
        user_data = {
            "username": "new_user",
            "password": "some_user_password123",
        }

        response = self.client.post(self.url, user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
        self.assertIn('Неверный логин или пароль', response.content.decode())

    def test_wrong_password(self):
        user_data = {
            "username": "some_user",
            "password": "new_user_password123",
        }

        response = self.client.post(self.url, user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
        self.assertIn('Неверный логин или пароль', response.content.decode())

    def test_user_already_confirm_register(self):
        self.user.is_active = True
        self.user.save()

        user_data = {
            "username": "some_user",
            "password": "some_user_password123",
        }

        response = self.client.post(self.url, user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
        self.assertIn("Email has already been confirmed", response.content.decode())


class LoginAPIViewTest(APITestCase):
    """тест логина и создания токенов"""

    def setUp(self):
        self.user = User.objects.create_user(
            username="some_user",
            email="some_user@example.com",
            password="some_user_password123",
            is_active=True)

        self.login_url = reverse("login")  # http://127.0.0.1:8000/api/users/login
        self.logout_url = reverse("logout")

    def tearDown(self):
        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content.decode())
        # Проверяем, что в следующем запросе пользователь не аутентифицирован:
        response = self.client.get('/users/')  # work only for permissions.IsAuthenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        # or:
        request = self.client.get(self.login_url).wsgi_request
        self.assertIsInstance(request.user, AnonymousUser)

    def test_login_successfull(self):
        user_data = {
            "username": "some_user",
            "password": "some_user_password123",}

        response = self.client.post(self.login_url, user_data)
        # print(f'---self.client.cookies is: {self.client.cookies}')
        """
        response.cookies.keys() = dict_keys(['access_token', 'refresh_token'])
        Set-Cookie: access_token=eyJhbGciOi...; 
        expires=Thu, 20 Mar 2025 17:03:22 GMT; HttpOnly; Max-Age=900; Path=/; SameSite=Lax; Secure
        Set-Cookie: refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6I....; 
        expires=Thu, 27 Mar 2025 16:48:22 GMT; HttpOnly; Max-Age=604800; Path=/; SameSite=Lax; Secure
        """

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Login successful', response.content.decode())

        # если токены установлены - появятся соответствующие ключи, проверяю наличие этих ключей:
        self.assertIn("access_token", response.cookies, "Access-token в cookie не установлен")
        self.assertIn("refresh_token", response.cookies, "Refresh-token в cookie не установлен")
        # проверка значений - что токен записался:
        self.assertNotEqual(response.cookies["access_token"].value, "")
        self.assertNotEqual(response.cookies["refresh_token"].value, "")
        # print(f'---access_token is {response.cookies["access_token"].value}')
        # print(f'---refresh_token is {response.cookies["refresh_token"].value}')

        # проверяю, что куки HttpOnly:
        self.assertTrue(response.cookies["access_token"]["httponly"], "Access token не HttpOnly")
        self.assertTrue(response.cookies["refresh_token"]["httponly"], "Refresh token не HttpOnly")
        # print(f'---access_token is httponly: {response.cookies["access_token"]["httponly"]}')

        # проверяю, что юзер залогинен:
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # print(f'---response.cookies is: {response.cookies}')
        # print(f'---self.client.cookies is: {self.client.cookies}')
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        # request = self.client.get('/users/').wsgi_request
        # self.assertIsInstance(request.user, AbstractBaseUser)


    def test_user_already_logged_in(self):
        user_data = {
            "username": "some_user",
            "password": "some_user_password123"}

        # логиню юзера:
        # self.client.login(**user_data) - нет
        response = self.client.post(self.login_url, user_data)

        self.assertIn("access_token", response.cookies, "Access-token в cookie не установлен")
        self.assertIn("refresh_token", response.cookies, "Refresh-token в cookie не установлен")
        self.assertNotEqual(response.cookies["access_token"].value, "")
        self.assertNotEqual(response.cookies["refresh_token"].value, "")

        # проверяю, что юзер залогинен:
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

        # пытаюсь логиниться повторно:
        response = self.client.post(self.login_url, user_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Вы уже вошли в систему.", response.content.decode())


    def test_login_user_not_registered(self):
        user_data = {
            "username": "new_user",
            "password": "new_user_password123", }

        response = self.client.post(self.login_url, user_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
        self.assertIn('Invalid credentials', response.content.decode())

        # токенов не должно быть в куках:
        self.assertNotIn("access_token", response.cookies, "Access-token найден в cookie")
        self.assertNotIn("refresh_token", response.cookies, "Refresh-token найден в cookie")

        # проверяю, что юзер не залогинен:
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_login_wrong_credentials(self):
        invalid_cases = [
            {"user_data": {"username": "some", "password": "some_user_password123"}, "message": "Invalid credentials"},
            {"user_data": {"username": "some_user", "password": "wrong_password"}, "message": "Invalid credentials"}

        ]
        for case in invalid_cases:
            with self.subTest(msg=case["message"]):

                response = self.client.post(self.login_url, case["user_data"])

                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content.decode())
                self.assertIn('Invalid credentials', response.content.decode())
                self.assertNotIn("access_token", response.cookies, "Access-token в найден в cookie")
                self.assertNotIn("refresh_token", response.cookies, "Refresh-token найден в cookie")

                # проверяю, что юзер не залогинен:
                response = self.client.get('/users/')
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
                self.assertFalse(response.wsgi_request.user.is_authenticated)


class LogoutAPIViewTest(APITestCase):
    def setUp(self):

        # создаю юзера и логиню его:
        self.user = User.objects.create_user(
            username="some_user",
            email="some_user@example.com",
            password="some_user_password123",
            is_active=True)

        self.login_url = reverse("login")
        self.logout_url = reverse("logout")

        login_data = {"username": "some_user", "password": "some_user_password123"}
        response = self.client.post(self.login_url, login_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Login successful', response.content.decode())
        self.assertIn("access_token", response.cookies, "Access-token в cookie не установлен")
        self.assertIn("refresh_token", response.cookies, "Refresh-token в cookie не установлен")

        # проверяю, что юзер залогинен:
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

        print("Логин успешен! Токены установлены в Cookies")

    def test_logout_successfull(self):

        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Logout successful', response.content.decode())

        # Проверяем, что токены удалены из cookies:
        # зная, что при логауте удаляется только значение ключей:
        self.assertEqual(response.cookies["access_token"].value, "")
        self.assertEqual(response.cookies["refresh_token"].value, "")

        # Проверяем, что max_age = 0 (истечение)
        self.assertEqual(response.cookies["access_token"]["max-age"], 0)
        self.assertEqual(response.cookies["refresh_token"]["max-age"], 0)

        # проверяю, что юзер не залогинен:
        response = self.client.get('/users/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

        print("Логаут успешен! Cookies очищены.")


class ResetPasswordAPIViewTest(APITestCase):

    def setUp(self):
        # создание тестового юзера:
        self.user = User.objects.create_user(
            username="some_user",
            email="some_user@example.com",
            password="some_user_password123",
            is_active=True
        )

        self.url = reverse("reset_password")

    def test_create_token_uid_successfull(self):
        """проверка что токен и юид создаются корректно"""

        user_data = {
            "email": "some_user@example.com"
        }

        response = self.client.post(self.url, user_data)

        # извлекаю uid и token из ссылки письма:
        self.assertEqual(len(mail.outbox), 1)  # проверяю, что отправлено письмо
        self.assertIn("Восстановление пароля", mail.outbox[0].subject)
        # разбираю ссылку:
        text = mail.outbox[0].body
        print(f'path: {text}')
        # регулярка для извлечения uid и token:
        match = re.match(r"^.*/change_password/(?P<uid>[^/]+)/(?P<token>[^/]+)/?$", text)
        # проверяю, что uid и token присутствуют:
        self.assertIsNotNone(match, "URL не содержит uid и token")
        self.uid = match.group("uid")
        self.token = match.group("token")
        self.assertTrue(self.uid, "UID отсутствует")
        self.assertTrue(self.token, "Token отсутствует")


    @patch('authapp.views.send_mail')
    def test_reset_password_successfull(self, mock_send_mail):

        user_data = {
            "email": "some_user@example.com"
        }

        response = self.client.post(self.url, user_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Если email существует, мы отправили ссылку для сброса пароля", response.content.decode())
        # проверяю, что письмо отправляется:
        mock_send_mail.assert_called_once()
        # проверяю содержимое письма:
        called_args, called_kwargs = mock_send_mail.call_args  # достаю аргументы последнего вызова
        print(f'called_args: {called_args}')  #  ('Восстановление пароля', 'Перейдите по ссылке...
        print(f'called_kwargs: {called_kwargs}')  # fail_silently=False
        self.assertEqual(called_args[0], 'Восстановление пароля')
        self.assertRegex(called_args[1], r'Перейдите по ссылке для сброса пароля: '
                                         r'http://localhost:8000/api/auth/change_password/.+/.+')
        self.assertEqual(called_args[2], 'no-reply@yourdomain.com')
        self.assertEqual(called_args[3], ['some_user@example.com'])


    @patch('authapp.views.send_mail')
    def test_reset_password_wrong_email(self, mock_send_mail):

        user_data = {
            "email": "wrong_email@example.com"
        }

        response = self.client.post(self.url, user_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Если email существует, мы отправили ссылку для сброса пароля", response.content.decode())
        # проверяю что письмо не отправляется:
        mock_send_mail.assert_not_called()


class ChangePasswordAPIViewTest(APITestCase):

    def setUp(self):

        self.user = User.objects.create_user(
            username="some_user",
            email="some_user@example.com",
            password="some_user_password123",
            is_active=True
        )

        # создаю токен и uid:
        self.token = default_token_generator.make_token(self.user)
        self.uid = urlsafe_base64_encode(force_bytes(self.user.id))
        # создаю ссылку с параметрами:
        self.change_url = reverse("change_password", kwargs={"uid": self.uid, "token": self.token})

    def test_change_password_successfull(self):
        user_data = {
            "new_password": "new_password123",
            "confirm_password": "new_password123"
        }

        response = self.client.post(self.change_url, user_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Пароль успешно изменен.")
        # обновлю юзера в бд и проверю что установился новый пароль:
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("new_password123"))

    def test_change_password_not_match(self):
        invalid_data = {
            "new_password": "new_password123",
            "confirm_password": "other_password123"
        }

        response = self.client.post(self.change_url, invalid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Пароли не совпадают.", response.content.decode())

    def test_change_password_invalid_data(self):
        invalid_data = {
            "new_password": "123",
            "confirm_password": "123"
        }

        response = self.client.post(self.change_url, invalid_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # self.assertIn("Пароли не совпадают.", response.content.decode())


    def test_change_password_invalid_uid_or_user_not_found(self):
        user_data = {
            "new_password": "new_password123",
            "confirm_password": "new_password123"
        }
        # создаю ссылку с невалидным uid:
        invalid_uid = urlsafe_base64_encode(force_bytes(2))
        self.change_url = reverse("change_password", kwargs={"uid": invalid_uid, "token": self.token})

        response = self.client.post(self.change_url, user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Недействительная ссылка.")


    def test_change_password_invalid_token(self):
        user_data = {
            "new_password": "new_password123",
            "confirm_password": "new_password123"
        }
        # создаю ссылку с невалидным токеном:
        self.change_url = reverse("change_password", kwargs={"uid": self.uid, "token": "some_invalid_token"})

        response = self.client.post(self.change_url, user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Недействительный токен.")











