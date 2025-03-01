from rest_framework import serializers
from .models import Note

class NoteSerializer(serializers.ModelSerializer):
    """Serializer for Note model."""
    class Meta:
        model = Note
        fields = ['id', 'title', 'content', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        """Create and return a new note."""
        # Get the user from the request
        user = self.context['request'].user
        # Add the user to the validated data
        validated_data['user'] = user
        return super().create(validated_data) 