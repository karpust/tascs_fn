from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import permissions, viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView

from tasks_project.settings import DOMAIN_NAME
from users.serializers import GroupSerializer, UserSerializer, RegisterSerializer, ChangePasswordSerializer
from users.utils import send_verification_email
from django.core.cache import cache
from django.urls.base import reverse
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import AuthenticationFailed


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('name')
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    # authentication_classes = [JWTAuthentication]

class RegisterAPIView(APIView):
    """
    API endpoint регистрации пользователя
    """
    # renderer_classes = [JSONRenderer, BrowsableAPIRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)  # нет инстанса, значит создание а не обновление
        # request.data — данные, отправлены пользователем в теле POST-запроса: имя, почта и пароль
        if serializer.is_valid():
            user = serializer.save()

            send_verification_email(user)  # вызывает send_mail

            return Response({
                "message": "Спасибо за регистрацию! "
                           "На ваш email было отправлено письмо-подтверждение. "
                           "Пожалуйста, пройдите по ссылке из письма."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # кроме статуса вернет и словарь, где ключи имена полей,
        # а значения — списки ошибок, связанных с каждым полем


class ConfirmRegisterAPIView(APIView):
    """Обработчик для подтверждения email через GET-запрос."""

    permission_classes = [permissions.AllowAny]

    queryset = User.objects.all()

    def get(self, request):
        # check if token in request:
        token = request.query_params.get('token')
        if not token:
            return Response({
                "error": "The token was expired or not provided",
                "action": "Request a new letter of confirmation by the link below.",
                "resend_url": request.build_absolute_uri(reverse('repeat_confirm_register'))
            }, status=status.HTTP_400_BAD_REQUEST)
        # check if token still in cache:
        token_data = cache.get(f"email_verification_token_{token}")
        cache.delete(f'email_verification_token_{token}')

        if not token_data:
            return Response({
                "error": "The link has invalid token.",
                "action": "Request a new letter of confirmation by the link below.",
                "resend_url": request.build_absolute_uri(reverse('repeat_confirm_register'))
            }, status=status.HTTP_400_BAD_REQUEST)

        # get user from token:
        user_id = token_data['user_id']

        # find this user in db:
        try:
            user = User.objects.get(id=user_id)

            if not user.is_active:
                user.is_active = True
                user.save()
                return Response({'message': 'Email is successfully confirmed. You can enter the system.'}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Email has already been confirmed. You can enter the system.'}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            raise ObjectDoesNotExist("The user was not found. Please, repeat the registration.")


class RepeatConfirmRegisterAPIView(APIView):
    """обработчик запроса на повторное письмо подтверждения email"""

    permission_classes = [permissions.AllowAny]

    def post(self, request):

        username = request.data['username']
        password = request.data['password']

        # проверка что юзер в бд и пароль совпадает:
        user = User.objects.filter(username=username).first()  # if not - user=None
        if not user or not check_password(password, user.password):  # сравниваю с хешем пароля
            return Response({'error': "Неверный логин или пароль"}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_active:
            return Response({
                'detail': 'Email has already been confirmed. You can enter the system.'},
                status=status.HTTP_400_BAD_REQUEST)  # редиректнуть на логин

        # отправление письма-подтверждения со ссылкой:
        send_verification_email(user)
        return Response({"message": "На ваш email было отправлено письмо-подтверждение. "
                                    "Пожалуйста, пройдите по ссылке из письма."})


class LoginAPIView(APIView):
    """
    обработчик логина, записывает создает токены и кладет в HttpOnly Cookies
    """
    # {"username": "mamba", "password": "1234"}
    permission_classes = [AllowAny]

    def post(self, request):
        user = request.user

        # проверяем, авторизован ли пользователь, передал ли он токен:
        if user.is_authenticated:
            return Response({
                "message": "Вы уже вошли в систему.",
                "detail": "Выйдите перед повторным входом."
            }, status=status.HTTP_400_BAD_REQUEST)

        # если пользователь не залогинен, продолжаем аутентификацию:
        username = request.data.get("username")
        password = request.data.get("password")
        # проверяем есть ли такой юзер с паролем в системе:
        user = authenticate(request, username=username, password=password)
        if user:

            # генерация нового JWT-токена:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response({"message": "Login successful"})
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE"],
                value=access_token,
                # expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                httponly=True,
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
                max_age=15 * 60,  # 15 минут
            )
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                # expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                httponly=True,
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
                max_age=7 * 24 * 60 * 60,  # 7 дней
            )

            return response

        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    """Обработчик выхода юзера и удаления его токенов из кук"""
    def post(self, request):
        response = Response({"message": "Выход выполнен"})
        response.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])  # access-token
        response.delete_cookie("refresh_token")
        response.data = {
            "message": "Logout successful"
        }
        return response


class RefreshTokenAPIView(APIView):
    """
    Вызывается клиентом для обновления рефреш-токена,
    когда он получает ответ сервера 401 Unauthorized или
    заранее вычислив время истечения токена.
    Лучше автоматически обновлять токен за 1 минуту до истечения.
    """

    permission_classes = [AllowAny]  # IsAuthenticated будет требовать действительный access_token, а он возможно истек и есть только refresh

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            raise AuthenticationFailed("Токен обновления отсутствует")

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
        except Exception:
            raise AuthenticationFailed("Недействительный refresh-токен")

        response = Response({"message": "Токен обновлен"})
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=access_token,
            httponly=True,
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            max_age=15 * 60,  # 15 минут
        )
        return response


class ResetPasswordAPIView(APIView):

    def post(self, request):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()

        if user:
            # создаю токен встроенными методами джанги:
            token = default_token_generator.make_token(user)  # создает одноразовый токен используя данные юзера
            uid = urlsafe_base64_encode(force_bytes(user.pk))  # кодирует id юзера в Base64 (URL-безопасный формат)
            # чтобы передавать uid в URL без спецсимволов
            # change_link = f"{DOMAIN_NAME}{reverse('change_password', kwargs=)}{uid}/{token}"
            change_link = f'{DOMAIN_NAME}{reverse("change_password", kwargs={"uid": uid, "token": token})}'

            # Отправка email:
            send_mail(
                "Восстановление пароля",
                f"Перейдите по ссылке для сброса пароля: {change_link}",
                "no-reply@yourdomain.com",
                [email],
                fail_silently=False,
            )

        # отправляем одинаковый ответ, чтобы не раскрывать существование email:
        return Response({"detail": "Если email существует, мы отправили ссылку для сброса пароля."},
                        status=status.HTTP_200_OK)


class ChangePasswordAPIView(APIView):

    def post(self, request, uid, token):
        try:
            # находим юзера в бд по id:
            uid = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=uid)

            # генерит токен по данным юзера и сравнивает с токеном из запроса:
            if not default_token_generator.check_token(user, token):
                return Response({"detail": "Недействительный токен."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ChangePasswordSerializer(data=request.data)
            if serializer.is_valid():
                user.set_password(serializer.validated_data["new_password"])
                user.save()
                return Response({"detail": "Пароль успешно изменен."}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Недействительная ссылка."}, status=status.HTTP_400_BAD_REQUEST)
