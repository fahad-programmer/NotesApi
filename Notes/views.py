from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Note
from .serializers import NoteSerializer, UserSerializer
from django.contrib.auth import authenticate, login, get_user_model
from rest_framework.decorators import api_view, action
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from rest_framework import viewsets, permissions


User = get_user_model()



@api_view(['POST'])
def get_user_from_token(request):
    # Get the token from the request body
    token = request.data.get('key')
    # Get the user associated with the token
    try:
        user = Token.objects.get(key=token).user
        # Return the user's details in the response
        return Response({
            'username': user.username,
            'id': user.id,
        })
    except Token.DoesNotExist:
        # Return an error if the token is invalid
        return Response({'error': 'Invalid token'}, status=401)


class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()
    serializer_class = NoteSerializer
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        user = self.request.user
        return Note.objects.filter(user=user.id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        serializer.save(user=user)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        user = request.user  # Get the authenticated user
        # Set the user field of the updated note to the authenticated user
        serializer.save(user=user)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        user = request.user  # Get the authenticated user
        if instance.user == user:  # Check if the authenticated user is the owner of the note
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            # Return a 403 Forbidden response if the user is not the owner
            return Response(status=status.HTTP_403_FORBIDDEN)



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            if User.objects.filter(email=request.data['email']).exists():
                return Response({"message":"Email Already Exists"}, status=status.HTTP_400_BAD_REQUEST)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
        except IntegrityError:
            return Response({"message": "Username or email is already in use"}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError:
            return Response({"message":"Invalid Data Check Your Input Please"})

        # Generate a token for the newly created user
        user = User.objects.get(pk=serializer.data['id'])
        token, created = Token.objects.get_or_create(user=user)

        # Return the token in the response
        return Response({'token': token.key}, status=status.HTTP_201_CREATED, headers=headers)


    def login(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            token = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            return Response({"message":"Username Or Password Is Incorrect"},status=status.HTTP_401_UNAUTHORIZED)


class NoteSearchViewSet(viewsets.ModelViewSet):
    # Use token authentication
    authentication_classes = [TokenAuthentication]
    # Use the Note model
    queryset = Note.objects.all()
    # Use the NoteSerializer
    serializer_class = NoteSerializer
    # Only allow authenticated users to access the API
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return notes for the authenticated user
        return Note.objects.filter(user=self.request.user)

    @action(detail=False, methods=['get'])
    def search(self, request, term):
        # Get the search term from the URL
        search_term = term
        # Get all notes for the authenticated user
        notes = self.get_queryset()
        # Filter the notes by the search term
        matching_notes = notes.filter(title__contains=search_term)
        # Serialize the matching notes
        serializer = self.get_serializer(matching_notes, many=True)
        # Return the serialized data in the API response
        return Response(serializer.data)
