from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('i18n/', include('django.conf.urls.i18n')),
    path('admin/', admin.site.urls),
    path('', include('asymmetric_jwt_auth.urls')),
]
