from django.http import HttpResponse
from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Note
from .serializers import NoteSerializer, LoginSerializer
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def get_csrf_token(request):
    return HttpResponse(request.META["CSRF_COOKIE"], content_type="text/plain")



class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()
    serializer_class = NoteSerializer
    # authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        user = self.request.user
        return Note.objects.filter(user=user.id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class LoginView(APIView):
    def post(self, request):
        # Deserialize the request data
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Get the login credentials
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        # Authenticate the user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Login the user
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
            # Return a success response

        else:
            # Return a 401 Unauthorized error if the authentication fails
            return Response(status=status.HTTP_401_UNAUTHORIZED)