"""
URL configuration for userform project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from userform import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
        path('admin/', admin.site.urls),
    path('login/',views.loginpage,name='loginpage'),
    path('signup/',views.index),
    path('',views.dashboard,name='dashboard'),
    path('f-password-verify/',views.forgetpassword),
    path('new-password/',views.newpassword),
    path('creatorsignup/',views.creatorsignup),
    path('adminsignup/', views.adminsignup, name='adminsignup'),
    path('uploadmlproject/',views.creatorprojects),
    path('creatorlogin/',views.creator_login),
    path('profile/', views.user_profile, name='user_profile'),
    path('logout/',views.logout_func,name='logout'),
    path('addmlproject/',views.upload_project),
    path('approve/<int:project_id>/', views.approve_project, name='approve_project'),
    path('reject/<int:project_id>/', views.reject_project, name='reject_project'),
    path('adminapprove/',views.review_projects),
    path('creator/info/<int:creator_id>/', views.get_creator_info, name='creator_info'),
    path('get_model/',views.get_model),
    path('use_project/<int:project_id>/',views.use_project),
    path('download_project/<int:project_id>/', views.download_project_file, name='download_project_file'),
    path('aboutus/',views.aboutus),
    path('delete-temp-image/', views.delete_temp_image, name='delete_temp_image'),
    path("refresh-detected/", views.refresh_detected, name="refresh_detected"),


]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
