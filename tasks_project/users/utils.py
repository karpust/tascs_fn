import uuid
from datetime import timedelta
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
from tasks_project.settings import DOMAIN_NAME


time_email_verification = 10


def generate_email_verification_token(user):
    """Генерирует UUID-токен только для подтверждения email."""
    token = uuid.uuid4()  # генерит уникальный id
    created_at = timezone.now()  # время создания
    lifetime = timedelta(minutes=time_email_verification)  # время действия

    # Сохраняем токен в кэше:
    # LocMemCache - данные хранятся в RAM, внутри текущего процесса Django.
    cache.set(f"email_verification_token_{token}", {
        "user_id": user.id,
        "created_at": created_at  # только чтобы отобразить оставшееся время в ссылке
    }, timeout=lifetime.total_seconds())

    return token, created_at, lifetime


def create_verification_link(user):
    """
    Создает ссылку для верификации emal;
    В ссылку вшиты: url сервера, UUID-токен,
    время когда токен истекает.
    """
    token, created_at, lifetime = generate_email_verification_token(user)
    expiration_time = created_at + lifetime
    verification_link = f'{DOMAIN_NAME}/verify-email?token={token}&expires_at={expiration_time}'
    # request.build_absolute_uri(reverse('verify-email'))
    print(f"Sending verification email to {user.email} with URL: {verification_link}")
    return verification_link


def send_verification_email(user):
    """Отправляет email с токеном и ссылкой для подтверждения."""
    verification_link = create_verification_link(user)

    send_mail(
        'Подтверждение email',
        f'Пожалуйста, подтвердите свой email, перейдя по ссылке: {verification_link}',
        'noreply@yourdomain.com',
        [user.email]
    )