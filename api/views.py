from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404

from .models import Note
from .serializers import NoteSerializer
from core.permissions import IsAdmin, IsOwnerOrAdmin

# Create your views here.

class NoteViewSet(viewsets.ModelViewSet):
    """ViewSet for the Note model."""
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    
    def get_queryset(self):
        """Return notes for the current user."""
        user = self.request.user
        # Admin can see all notes
        if user.is_admin:
            return Note.objects.all()
        # Regular users can only see their own notes
        return Note.objects.filter(user=user)
    
    @action(detail=False, methods=['get'], permission_classes=[IsAdmin])
    def all(self, request):
        """Action to get all notes (admin only)."""
        notes = Note.objects.all()
        serializer = self.get_serializer(notes, many=True)
        return Response(serializer.data)
