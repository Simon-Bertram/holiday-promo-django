from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from .models import Note
from core.models import User

class NoteTests(TestCase):
    """Test the Note API endpoints"""
    
    def setUp(self):
        """Set up test client and create test users and notes"""
        self.client = APIClient()
        self.login_url = reverse('core:token_obtain_pair')
        
        # Create test users
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            username='adminuser',
            password='testpass123',
            role=User.Role.ADMIN
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            username='regularuser',
            password='testpass123',
            role=User.Role.USER
        )
        
        self.another_user = User.objects.create_user(
            email='another@example.com',
            username='anotheruser',
            password='testpass123',
            role=User.Role.USER
        )
        
        # Create test notes
        self.admin_note = Note.objects.create(
            user=self.admin_user,
            title='Admin Note',
            content='This is a note created by admin'
        )
        
        self.user_note = Note.objects.create(
            user=self.regular_user,
            title='User Note',
            content='This is a note created by regular user'
        )
        
        self.another_user_note = Note.objects.create(
            user=self.another_user,
            title='Another User Note',
            content='This is a note created by another user'
        )
        
        # Get tokens for authentication
        admin_login_response = self.client.post(
            self.login_url,
            {'email': 'admin@example.com', 'password': 'testpass123'},
            format='json'
        )
        self.admin_token = admin_login_response.data['access']
        
        user_login_response = self.client.post(
            self.login_url,
            {'email': 'user@example.com', 'password': 'testpass123'},
            format='json'
        )
        self.user_token = user_login_response.data['access']
        
        # API endpoints
        self.notes_url = reverse('api:note-list')
        self.all_notes_url = reverse('api:note-all')
        
    def test_get_user_notes(self):
        """Test getting a user's notes"""
        # Test as admin
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.get(self.notes_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)  # Admin can see all notes
        
        # Test as regular user
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        response = self.client.get(self.notes_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # User can only see their notes
        self.assertEqual(response.data[0]['title'], 'User Note')
        
        # Test without authentication
        self.client.credentials()
        response = self.client.get(self.notes_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_get_all_notes_admin_only(self):
        """Test getting all notes (admin-only endpoint)"""
        # Test as admin
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.get(self.all_notes_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)  # Should see all notes
        
        # Test as regular user
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        response = self.client.get(self.all_notes_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_create_note(self):
        """Test creating a new note"""
        payload = {
            'title': 'New Test Note',
            'content': 'This is a test note content'
        }
        
        # Test as authenticated user
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        response = self.client.post(self.notes_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], 'New Test Note')
        
        # Verify the note was created in the database
        self.assertTrue(Note.objects.filter(title='New Test Note').exists())
        
        # Test without authentication
        self.client.credentials()
        response = self.client.post(self.notes_url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_get_specific_note(self):
        """Test getting a specific note"""
        # Test getting own note
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        url = reverse('api:note-detail', args=[self.user_note.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'User Note')
        
        # Test getting someone else's note (should fail for regular user)
        url = reverse('api:note-detail', args=[self.another_user_note.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Test as admin getting someone else's note (should succeed)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Another User Note')
    
    def test_update_note(self):
        """Test updating a note"""
        payload = {
            'title': 'Updated Note Title',
            'content': 'Updated note content'
        }
        
        # Test updating own note
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        url = reverse('api:note-detail', args=[self.user_note.id])
        response = self.client.put(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Updated Note Title')
        
        # Verify database was updated
        self.user_note.refresh_from_db()
        self.assertEqual(self.user_note.title, 'Updated Note Title')
        
        # Test updating someone else's note (should fail for regular user)
        url = reverse('api:note-detail', args=[self.another_user_note.id])
        response = self.client.put(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Test as admin updating someone else's note (should succeed)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.put(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify database was updated
        self.another_user_note.refresh_from_db()
        self.assertEqual(self.another_user_note.title, 'Updated Note Title')
    
    def test_delete_note(self):
        """Test deleting a note"""
        # Test deleting own note
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        url = reverse('api:note-detail', args=[self.user_note.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify the note was deleted
        self.assertFalse(Note.objects.filter(id=self.user_note.id).exists())
        
        # Test deleting someone else's note (should fail for regular user)
        url = reverse('api:note-detail', args=[self.another_user_note.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Test as admin deleting someone else's note (should succeed)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify the note was deleted
        self.assertFalse(Note.objects.filter(id=self.another_user_note.id).exists())