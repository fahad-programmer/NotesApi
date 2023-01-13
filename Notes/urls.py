from django.urls import include, path
from rest_framework import routers
from . import views
from rest_framework.authtoken.views import obtain_auth_token 

router = routers.DefaultRouter()
router.register(r'notes', views.NoteViewSet),

urlpatterns = [
    path('', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'), 
    path('user-detail/', views.get_user_from_token, name='get_user_from_token'),
    path('users/', views.UserViewSet.as_view({
        'post': 'create'
    })),
    path('users/login/', views.UserViewSet.as_view({
        'post': 'login'
    })),
    path('search/<str:term>/', views.NoteSearchViewSet.as_view({'get': 'search'}), name='search_note')

]
