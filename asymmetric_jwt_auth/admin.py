from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from asymmetric_jwt_auth.models import PublicKey


class PublicKeyInline(admin.StackedInline):
    model = PublicKey
    can_delete = True
    verbose_name_plural = 'public keys'


class UserAdmin(UserAdmin):
    inlines = (PublicKeyInline, )


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
