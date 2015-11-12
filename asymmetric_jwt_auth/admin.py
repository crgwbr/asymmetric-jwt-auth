from django.contrib import admin
from . import models
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from asymmetric_jwt_auth.models import PublicKey

@admin.register(models.PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ['user', 'comment']
