# ip_tracking/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('test/', views.test_logging_view, name='test_logging'),
    path('logs/', views.view_logs, name='view_logs'),
    path('api/logs/', views.api_logs, name='api_logs'),
]
