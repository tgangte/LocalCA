'''
This module contains the URL patterns for the LocalCA application.
'''

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Homepage (public view)
    path('', views.homepage, name='homepage'),

    # Logged-in user home (private view with access to private keys)

    path('download/<int:serial_number>/', views.download, name='download'),

    # Create root certificate authority
    path('create_ca/', views.create_ca, name='create_ca'),

    # Create intermediate certificate authority
    path(
        'create_intermediate/',
        views.create_intermediate,
        name='create_intermediate'),

    # Create leaf certificate
    path('create_leaf/', views.create_leaf, name='create_leaf'),

    # Revoke a certificate
    path(
        'revoke_certificate/<int:cert_id>/',
        views.revoke_certificate,
        name='revoke_certificate'),

    path(
        'download_private/<str:serial_number>/',
        views.download_private,
        name='download_private'),

    path(
        'download_pkcs12/<str:serial_number>/',
        views.download_pkcs12,
        name='download_pkcs12'),

    # Authentication URLs
    path('login/', auth_views.LoginView.as_view(
        template_name='admin/login.html',
        extra_context={'site_header': 'Local CA Manager'}
    ), name='login'),
    path('logout/', auth_views.LogoutView.as_view(
        template_name='registration/logged_out.html',
        next_page='homepage'
    ), name='logout'),
]
