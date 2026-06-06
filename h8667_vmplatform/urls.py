"""
URL configuration for h8667_vmplatform project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
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
from django.urls import include
from resize.views import sso_logout_init

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('resize.urls')),
    path('domain/', include('domain.urls')),
    # SSO 退出初始化（用户点击退出）
    path('logout/', sso_logout_init, name='sso_logout_init'),
]
