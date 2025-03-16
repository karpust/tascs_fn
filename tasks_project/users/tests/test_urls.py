from django.test import SimpleTestCase
from django.urls import reverse, resolve
from users.views import RegisterAPIView

class URLTestCase(SimpleTestCase):  #?
    def test_register_url_resolves(self):
        """Проверка, что URL register/ вызывает правильную вью"""
        url = reverse("register")  # беру URL по имени
        self.assertEqual(resolve(url).func.view_class, RegisterAPIView)  #?
