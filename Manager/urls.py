from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from users import urls as user_urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(user_urls))
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
