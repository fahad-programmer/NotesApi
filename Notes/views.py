from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Note, UserActions, Profile
from .serializers import NoteSerializer, UserSerializer, UserActionsSerializer, PasswordUpdateSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from django.contrib.auth import authenticate, get_user_model
from rest_framework.decorators import api_view, action
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from rest_framework import viewsets, permissions
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, update_session_auth_hash
from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_exempt
from django.utils.crypto import get_random_string
from django.core.mail import send_mail



User = get_user_model()





class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()
    serializer_class = NoteSerializer
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        user = self.request.user
        return Note.objects.filter(user=user.id, is_deleted=False)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        serializer.save(user=user)

        #Creating user actions
        user_act = UserActions.objects.create(user=user, action=f"Dear {user.username} You Created A Note")
        user_act.save()

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

        #Creating user actions
        user_act = UserActions.objects.create(user=user, action=f"Dear {user.username} You Updated A Note")
        user_act.save()

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        #Creating user actions
        user_act = UserActions.objects.create(user=request.user, action=f"Dear {request.user.username} You Created A Note")
        user_act.save()

        self.perform_destroy(instance)

        return Response(status=status.HTTP_200_OK)


    
    def trash(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.trash()
        return Response(status=status.HTTP_200_OK)

    def restore(self, request, pk=None, *args, **kwargs):
        try:
            note = Note.objects.get(pk=pk)
        except Note.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        #Making it un-deleted
        note.restore()
        return Response(status.HTTP_200_OK)

    


 
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
            token, created = Token.objects.get_or_create(user=user)
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
    



class TrashView(viewsets.ModelViewSet):
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
        return Note.objects.filter(user=self.request.user, is_deleted=True)

    @action(detail=False, methods=['get'])
    def TrashNotes(self, request):
        # Get all notes for the authenticated user
        notes = self.get_queryset()
        # Filter the notes by the search term
        # Serialize the matching notes
        serializer = self.get_serializer(notes, many=True)
        # Return the serialized data in the API response
        return Response(serializer.data)





@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_user_actions(request):
    user_actions = UserActions.objects.filter(user=request.user).order_by('-created_at')[:5]
    serializer = UserActionsSerializer(user_actions, many=True)
    UserActions.objects.exclude(pk__in=user_actions).delete()
    return Response(serializer.data)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def password_update_api(request):
    if request.method == 'POST':
        serializer = PasswordUpdateSerializer(data=request.data.copy(), context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password has been updated."}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    def post(self, request, format=None):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            # if Profile.objects.get(user=user)[0].reset_password_pin:
            #     return Response({'error': 'A reset password PIN has already been generated for this user.'}, status=status.HTTP_400_BAD_REQUEST)

            if Profile.objects.filter(user=user).first().reset_password_pin:
                return Response({"message":"Already Available"})

            pin = get_random_string(length=6, allowed_chars='1234567890')
            user_profile = Profile.objects.create(user=user, reset_password_pin=pin)
            user_profile.save()

            subject = 'Password Reset PIN'
            message = f'Your password reset PIN is {pin}. Please enter this PIN in the app to reset your password.'
            from_email = 'no-reply@example.com'
            recipient_list = [email]
            send_mail(subject, message, from_email, recipient_list)

            return Response({'success': 'An email has been sent to you with your password reset PIN.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class ResetPasswordView(APIView):
    def post(self, request, format=None):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            pin = serializer.validated_data['pin']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                profile = Profile.objects.get(user=user)
            except Profile.DoesNotExist:
                return Response({'error': 'Profile matching query does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            if profile.reset_password_pin != pin:
                return Response({'error': 'Invalid reset password PIN.'}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(password)
            user.save()
            profile.reset_password_pin = None
            profile.save()

            return Response({'success': 'Your password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@authentication_classes([TokenAuthentication])
class user_profile(APIView):
    def get(self, request):
        user = request.user
        number_of_notes = len(Note.objects.filter(user=user, is_deleted=False))
        return Response({'username': user.username, 'email': user.email, 'number_of_notes':number_of_notes})