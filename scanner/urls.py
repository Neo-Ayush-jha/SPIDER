from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('scanner/', views.index, name='scanner'),
    path('scanner/history/', views.scan_history, name='scan_history'),
    path('scanner/history/<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('api/start_scan/', views.start_scan, name='start_scan'),
    path('api/status/<int:scan_id>/', views.scan_status, name='scan_status'),
    path('api/export/<int:scan_id>/csv/', views.export_csv, name='export_csv'),
    path('api/export/<int:scan_id>/json/', views.export_json, name='export_json'),
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('payment/', views.make_payment, name='make_payment'),
    path('verify-payment/', views.verify_payment, name='verify_payment'),
]
