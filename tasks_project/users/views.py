from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets, status
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from users.serializers import GroupSerializer, UserSerializer, RegisterSerializer
from users.utils import send_verification_email


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    # permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('name')
    serializer_class = GroupSerializer
    # permission_classes = [permissions.IsAuthenticated]

class RegisterAPIView(APIView):
    # renderer_classes = [JSONRenderer, BrowsableAPIRenderer]
    # permission_classes = [permissions.AllowAny]

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