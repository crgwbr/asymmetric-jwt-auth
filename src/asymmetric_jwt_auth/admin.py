from django.contrib import admin
from . import models


@admin.register(models.PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ['user', 'comment']
    fields = ['user', 'comment', 'key']
    raw_id_fields = ['user']
