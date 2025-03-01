from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import NoteViewSet

app_name = 'api'

router = DefaultRouter()
router.register('notes', NoteViewSet, basename='note')

urlpatterns = [
    path('', include(router.urls)),
] 