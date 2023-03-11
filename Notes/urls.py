from django.urls import include, path
from rest_framework import routers
from . import views
from rest_framework.authtoken.views import obtain_auth_token 

router = routers.DefaultRouter()
router.register(r'notes', views.NoteViewSet),
router.register(r'trash', views.TrashView)

urlpatterns = [
    path('', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'), 
    path('user-detail/', views.user_profile, name='get_user_from_token'),
    path('users/', views.UserViewSet.as_view({
        'post': 'create'
    })),
    path('users/login/', views.UserViewSet.as_view({
        'post': 'login'
    })),
    path('search/<str:term>/', views.NoteSearchViewSet.as_view({'get': 'search'}), name='search_note'),
    path('user-action/', views.get_user_actions, name="User Action"),
    path('notes/<int:pk>/trash/', views.NoteViewSet.as_view({'post': 'trash'}), name='note-trash'),
    path('notes/<int:pk>/restore/', views.NoteViewSet.as_view({'post': 'restore'}), name='note-restore'),
    path('update-password', views.password_update_api, name="password-update"),
    path('forget-password', views.ForgotPasswordView.as_view(), name="forget-password"),
    path('reset-password', views.ResetPasswordView.as_view(), name="forget-password"),
    path('user-profile', views.user_profile.as_view(), name="user-profile"),
]


urlpatterns += router.urls