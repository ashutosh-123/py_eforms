from django.conf.urls import url, include
from django.contrib import admin
from rest_framework.authtoken import views
from django.conf.urls.static import static
from django.conf import settings
from eforms_app.views import apple_app_site_association
urlpatterns = [
    url(r'^jet/', include('jet.urls', 'jet')),
    url(r'^admin/', admin.site.urls),
    url(r'^api/v1/token/auth/', views.obtain_auth_token),
    url(r'api/v1/', include('eforms_app.urls')),
    url(r'^docs/', include('rest_framework_docs.urls')),
    url(r'^apple-app-site-association/$', apple_app_site_association),

]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

