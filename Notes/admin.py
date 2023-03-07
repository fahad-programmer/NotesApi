from django.contrib import admin
from .models import Note, UserActions, Profile


# Register your models here.
admin.site.register(Note)
admin.site.register(UserActions)
admin.site.register(Profile)
