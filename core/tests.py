from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
import json

from .models import MagicCode, User

User = get_user_model()

class AuthenticationTests(TestCase):
    """Test the authentication API endpoints"""
    
    def setUp(self):
        """Set up test client and create test user"""
        self.client = APIClient()
        self.register_url = reverse('core:register')
        self.login_url = reverse('core:token_obtain_pair')
        self.refresh_url = reverse('core:token_refresh')
        self.magic_code_request_url = reverse('core:request_magic_code')
        self.magic_code_verify_url = reverse('core:verify_magic_code')
        self.user_me_url = reverse('core:user_me')
        
        # Create an existing user for testing login
        self.user = User.objects.create_user(
            email='existing@example.com',
            username='existinguser',
            password='testpass123',
            first_name='Existing',
            last_name='User'
        )
        
    def test_user_registration(self):
        """Test that a user can register"""
        payload = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'testpass123',
            'password_confirm': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User'
        }
        
        # Test successful registration
        response = self.client.post(self.register_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='test@example.com').exists())
        
        # Test registration with existing email
        payload['username'] = 'newuser'
        response = self.client.post(self.register_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test registration with mismatched passwords
        payload = {
            'email': 'new@example.com',
            'username': 'newuser',
            'password': 'testpass123',
            'password_confirm': 'wrongpass',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.register_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_login(self):
        """Test that a user can login and get tokens"""
        payload = {
            'email': 'existing@example.com',
            'password': 'testpass123'
        }
        
        # Test successful login
        response = self.client.post(self.login_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        
        # Test login with invalid credentials
        payload['password'] = 'wrongpass'
        response = self.client.post(self.login_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_refresh(self):
        """Test refreshing tokens"""
        # First, get a refresh token
        login_payload = {
            'email': 'existing@example.com',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        refresh = login_response.data['refresh']
        
        # Test refreshing token
        refresh_payload = {'refresh': refresh}
        response = self.client.post(self.refresh_url, refresh_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        
        # Test with invalid refresh token
        refresh_payload = {'refresh': 'invalidtoken'}
        response = self.client.post(self.refresh_url, refresh_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_magic_code_request(self):
        """Test requesting a magic code"""
        payload = {'email': 'existing@example.com'}
        
        # Test successful request
        response = self.client.post(self.magic_code_request_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('email', response.data)
        
        # Test with non-existent email
        payload = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.magic_code_request_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_magic_code_verify(self):
        """Test verifying a magic code"""
        # Request a magic code first
        magic_code = MagicCode.generate_code(self.user)
        
        payload = {
            'email': 'existing@example.com',
            'code': magic_code.code
        }
        
        # Test successful verification
        response = self.client.post(self.magic_code_verify_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        
        # Verify the code is marked as used
        magic_code.refresh_from_db()
        self.assertTrue(magic_code.is_used)
        
        # Test with invalid code
        payload['code'] = 'invalidcode'
        response = self.client.post(self.magic_code_verify_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test with non-existent email
        payload = {
            'email': 'nonexistent@example.com',
            'code': magic_code.code
        }
        response = self.client.post(self.magic_code_verify_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_get_user_info(self):
        """Test getting user information"""
        # Login first to get token
        login_payload = {
            'email': 'existing@example.com',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        token = login_response.data['access']
        
        # Test with valid token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'existing@example.com')
        
        # Test with invalid token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken')
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Test without token
        self.client.credentials()
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_update_user_info(self):
        """Test updating user information"""
        # Login first to get token
        login_payload = {
            'email': 'existing@example.com',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        token = login_response.data['access']
        
        # Test updating with valid token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        update_payload = {
            'email': 'existing@example.com',  # Include required fields
            'username': 'existinguser',       # Include required fields
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        response = self.client.put(self.user_me_url, update_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        
        # Verify the database was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
