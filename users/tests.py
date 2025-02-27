from django.urls import reverse
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from .models import Referral

User = get_user_model()

class UserTests(APITestCase):
    def test_register_user(self):
        url = reverse('register')
        data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword123",
            "referral_code": "REF123",
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue('access' in response.data)

    def test_login_user(self):
        User.objects.create_user(username="testuser", email="test@example.com", password="testpassword123")
        url = reverse('login')
        data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('access' in response.data)

    def test_referral_system(self):
        referrer = User.objects.create_user(username="referrer", email="referrer@example.com", password="testpassword123", referral_code="REF123")
        url = reverse('register')
        data = {
            "username": "referred_user",
            "email": "referred@example.com",
            "password": "testpassword123",
            "referral_code": "REF123",
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        referral = Referral.objects.filter(referred_user__username="referred_user").first()
        self.assertIsNotNone(referral)
        self.assertEqual(referral.referrer.username, "referrer")