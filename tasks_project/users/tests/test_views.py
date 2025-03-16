from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.core.cache import cache
from django.core import mail

User = get_user_model()


class RegisterAPIViewTestCase(APITestCase):

    def setUp(self):
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "strongpassword123",
        }
        # self.url = reverse('register')  # получаем URL по имени
        self.url = '/register/'

    def test_register_user(self):
        """Тестируем регистрацию пользователя через API."""
        response = self.client.post(self.url, self.user_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("Спасибо за регистрацию", response.data["message"])

        user_exists = User.objects.filter(email=self.user_data["email"]).exists()
        self.assertTrue(user_exists)

        print(mail.outbox)  # список, в который попадают все отправленные письма при использовании django.core.mail.send_mail()
        self.assertEqual(len(mail.outbox), 1)  # проверяем, что отправлено 1 письмо
        self.assertIn("Подтверждение email", mail.outbox[0].subject)
        # print(f'mail.outbox[0].body = {mail.outbox[0].body}')
        # print(f'mail.outbox[0].subject = {mail.outbox[0].subject}')
        self.assertIn("verify-email", mail.outbox[0].body)

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










