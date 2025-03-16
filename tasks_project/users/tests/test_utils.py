import unittest
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
# from django.contrib.auth.models import User
from rest_framework.test import APITestCase

from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
from datetime import datetime
from unittest.mock import patch
from tasks_project.settings import DOMAIN_NAME
from users.utils import generate_email_verification_token, create_verification_link, send_verification_email

User = get_user_model()


class EmailVerificationUtilsTestCase(APITestCase):
    """
    правильный ли токен,
    правильная ли ссылка,
    отправляется ли письмо.
    """

    def setUp(self):
        self.user = User.objects.create_user(email="test@example.com", password="password123", username="testuser")

    def test_generate_email_verification_token(self):
        """
        Проверяет корректно ли генерируется и
        сохраняется в кэше UUID-токен, user_id, created_at
        """
        token, created_at, lifetime = generate_email_verification_token(self.user)

        self.assertIsInstance(token, uuid.UUID)
        self.assertIsInstance(created_at, datetime)
        self.assertEqual(lifetime, timedelta(minutes=10))

        cached_data = cache.get(f"email_verification_token_{token}")  # кэш
        self.assertIsNotNone(cached_data)
        self.assertEqual(cached_data["user_id"], self.user.id)
        self.assertEqual(cached_data["created_at"], created_at)

    @patch('users.utils.generate_email_verification_token')
    def test_create_verification_link(self, mock_generate_token):
        """
        Проверяет корректно ли генерируется ссылка подтверждения email
        """
        mock_token = uuid.uuid4()
        mock_created_at = timezone.now()
        mock_lifetime = timedelta(minutes=10)
        # мок-функция симулирует работу:
        mock_generate_token.return_value = (mock_token, mock_created_at, mock_lifetime)

        # create_verification_link вызывает mock_generate_token вместо generate_email_verification_token:
        verification_link = create_verification_link(self.user)
        expected_link = f'{DOMAIN_NAME}/verify-email?token={mock_token}&expires_at={mock_created_at + mock_lifetime}'

        # проверяю что ф-ция вызывается:
        mock_generate_token.assert_called_once()
        # сравниваем результ работы create_verification_link и ссылку собраную вручную:
        self.assertEqual(verification_link, expected_link)

    @patch('users.utils.send_mail')  # куда импортировали, оттуда и подменяем
    @patch('users.utils.create_verification_link')  # ф-ция проверена выше, можно мокать
    def test_send_verification_email(self, mock_create_link, mock_send_mail):
        """
        Проверяет отправляется ли письмо-подтвержение
        """
        mock_create_link.return_value = "http://testserver/verify-email?token=1234"

        send_verification_email(self.user)  # вызовет mock_create_link и mock_send_mail

        mock_create_link.assert_called_once_with(self.user)
        mock_send_mail.assert_called_once_with(
            'Подтверждение email',
            'Пожалуйста, подтвердите свой email, перейдя по ссылке: http://testserver/verify-email?token=1234',
            'noreply@yourdomain.com',
            [self.user.email]
        )

