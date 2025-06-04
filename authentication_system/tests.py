from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status

User = get_user_model()


class UserModelTests(TestCase):
    """Test cases for CustomUser model"""

    def test_create_user(self):
        """Test creating a user with email"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('testpass123'))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        """Test creating a superuser"""
        admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='testpass123'
        )
        self.assertEqual(admin_user.email, 'admin@example.com')
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)


class AuthenticationAPITests(APITestCase):
    """Test cases for authentication API endpoints"""

    def setUp(self):
        self.register_url = reverse('authentication_system:register')
        self.login_url = reverse('authentication_system:login')
        self.verify_email_url = reverse('authentication_system:verify-email')

    def test_user_registration(self):
        """Test user registration"""
        data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!',
            'password_confirm': 'TestPassword123!',
            'first_name': 'John',
            'last_name': 'Doe'
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='test@example.com').exists())

    def test_user_login(self):
        """Test user login"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        user.is_email_verified = True
        user.save()

        data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_email_verification(self):
        """Test email verification"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        code = user.generate_verification_code()

        data = {
            'email': 'test@example.com',
            'code': code
        }
        response = self.client.post(self.verify_email_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)


class GoogleAuthenticationTests(APITestCase):
    """Test cases for Google OAuth2 authentication"""

    def setUp(self):
        self.google_auth_url = reverse('authentication_system:google-auth')
        self.mock_google_user_info = {
            'email': 'testuser@gmail.com',
            'given_name': 'Test',
            'family_name': 'User',
            'id': '123456789',
            'verified_email': True
        }

    def test_google_auth_initiation_get(self):
        """Test GET request to initiate Google OAuth flow"""
        response = self.client.get(self.google_auth_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('auth_url', response.data)
        self.assertIn('accounts.google.com', response.data['auth_url'])

    def test_google_auth_missing_code(self):
        """Test POST request without authorization code"""
        response = self.client.post(self.google_auth_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_google_auth_invalid_code(self):
        """Test POST request with invalid authorization code"""
        data = {'code': 'invalid_code'}
        response = self.client.post(self.google_auth_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_google_auth_create_new_user(self):
        """Test Google authentication creating a new user"""
        # Mock the external API calls
        from unittest.mock import patch, MagicMock

        with patch.object(self.client, 'post') as mock_post, \
             patch('requests.post') as mock_token_request, \
             patch('requests.get') as mock_user_request:

            # Mock token exchange response
            mock_token_response = MagicMock()
            mock_token_response.json.return_value = {'access_token': 'mock_token'}
            mock_token_response.raise_for_status.return_value = None
            mock_token_request.return_value = mock_token_response

            # Mock user info response
            mock_user_response = MagicMock()
            mock_user_response.json.return_value = self.mock_google_user_info
            mock_user_response.raise_for_status.return_value = None
            mock_user_request.return_value = mock_user_response

            # Make the actual request
            data = {'code': 'valid_auth_code'}
            response = self.client.post(self.google_auth_url, data)

            if response.status_code == status.HTTP_200_OK:
                self.assertIn('token', response.data)
                self.assertIn('user', response.data)
                self.assertTrue(response.data['created'])
                self.assertEqual(response.data['user']['email'], 'testuser@gmail.com')

                # Verify user was created in database
                user = User.objects.get(email='testuser@gmail.com')
                self.assertTrue(user.is_email_verified)
                self.assertEqual(user.first_name, 'Test')
                self.assertEqual(user.last_name, 'User')

    def test_google_auth_existing_user(self):
        """Test Google authentication with existing user"""
        # Create existing user
        existing_user = User.objects.create_user(
            email='testuser@gmail.com',
            password='oldpassword',
            first_name='Old',
            last_name='Name'
        )

        from unittest.mock import patch, MagicMock

        with patch('requests.post') as mock_token_request, \
             patch('requests.get') as mock_user_request:

            # Mock token exchange response
            mock_token_response = MagicMock()
            mock_token_response.json.return_value = {'access_token': 'mock_token'}
            mock_token_response.raise_for_status.return_value = None
            mock_token_request.return_value = mock_token_response

            # Mock user info response
            mock_user_response = MagicMock()
            mock_user_response.json.return_value = self.mock_google_user_info
            mock_user_response.raise_for_status.return_value = None
            mock_user_request.return_value = mock_user_response

            # Make the actual request
            data = {'code': 'valid_auth_code'}
            response = self.client.post(self.google_auth_url, data)

            if response.status_code == status.HTTP_200_OK:
                self.assertIn('token', response.data)
                self.assertIn('user', response.data)
                self.assertFalse(response.data['created'])

                # Verify user info was updated
                existing_user.refresh_from_db()
                self.assertTrue(existing_user.is_email_verified)
                self.assertEqual(existing_user.first_name, 'Test')
                self.assertEqual(existing_user.last_name, 'User')

    def test_google_auth_url_in_main_api(self):
        """Test that Google auth URL is included in main API endpoints"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('google_auth', response.data['endpoints'])
