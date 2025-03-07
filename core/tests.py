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
        self.logout_url = reverse('core:logout')
        
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
        """Test that a user can login and get tokens in cookies"""
        payload = {
            'username': 'existinguser',
            'password': 'testpass123'
        }
        
        # Test successful login
        response = self.client.post(self.login_url, payload, format='json')
        print("Login response:", response.status_code)
        print("Response data:", response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that the cookies are set
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
        self.assertIn('csrftoken', response.cookies)
        
        # Check that the tokens are no longer in the response body
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)
        
        # Check that user data is in the response
        self.assertIn('user', response.data)
        
        # Check that the cookies are HTTP-only (except CSRF token)
        self.assertTrue(response.cookies['access_token']['httponly'])
        self.assertTrue(response.cookies['refresh_token']['httponly'])
        self.assertFalse(response.cookies['csrftoken']['httponly'])
        
        # Test login with invalid credentials
        payload['password'] = 'wrongpass'
        response = self.client.post(self.login_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_refresh(self):
        """Test refreshing tokens using HTTP-only cookies"""
        # First, login to get cookies
        login_payload = {
            'username': 'existinguser',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        
        # Store cookies for the next request
        self.client.cookies = login_response.cookies
        
        # Test refreshing token with cookie (no payload needed)
        response = self.client.post(self.refresh_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that the new access token cookie is set
        self.assertIn('access_token', response.cookies)
        
        # Check response has success message
        self.assertIn('detail', response.data)
        
        # Test with invalid/no refresh token
        # Clear cookies first
        self.client.cookies.clear()
        response = self.client.post(self.refresh_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_logout(self):
        """Test that logout clears the auth cookies"""
        # First, login to get cookies
        login_payload = {
            'username': 'existinguser',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        
        # Store cookies for the next request
        self.client.cookies = login_response.cookies
        
        # Make the logout request
        response = self.client.post(self.logout_url, {}, format='json')
        
        # Check that the response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that the cookies are cleared (set to expire in the past)
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)
        self.assertEqual(response.cookies['access_token']['max-age'], 0)
        self.assertEqual(response.cookies['refresh_token']['max-age'], 0)
        
        # Verify we can't access protected resources after logout
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_magic_code_request(self):
        """Test requesting a magic code"""
        payload = {
            'email': 'existing@example.com',
            'captcha_token': 'test-token'
        }
        
        # Test successful request
        response = self.client.post(self.magic_code_request_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('email', response.data)
        
        # Test with non-existent email
        payload = {
            'email': 'nonexistent@example.com',
            'captcha_token': 'test-token'
        }
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
        # Login first to get cookies
        login_payload = {
            'username': 'existinguser',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        
        # Store cookies for the next request
        self.client.cookies = login_response.cookies
        
        # Test with valid cookies
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'existing@example.com')
        
        # Test with invalid cookies
        self.client.cookies.clear()
        response = self.client.get(self.user_me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_update_user_info(self):
        """Test updating user information"""
        # Login first to get cookies
        login_payload = {
            'username': 'existinguser',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_payload, format='json')
        
        # Store cookies for the next request
        self.client.cookies = login_response.cookies
        
        # Test updating with valid cookies
        update_payload = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        response = self.client.patch(self.user_me_url, update_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')
        
        # Verify the database was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')
