from django.urls import path
from .views import ( RegisterUserView, LoginWithMFA,set_csrf_cookie,AccessFileView,GenerateTokenView,LogoutView,UserManagementView,RefreshTokenView,ListUsersView,SharedWithYouView, FileUploadView,GenerateMFASecretView,EnableMFAView, FileListView, ManageUsersView, ManageFilesView, DownloadFileView,VerifyMFAView)

urlpatterns = [
    path('csrf/', set_csrf_cookie, name='set_csrf_cookie'),
    path('refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('users/', ListUsersView.as_view(), name='list_users'),
    path('login/', LoginWithMFA.as_view(), name='login'),
    path('logout/',LogoutView.as_view(), name='logout'),
    path('files/<int:file_id>/share/', GenerateTokenView.as_view(), name='generate_token'),
    path('files/access/<str:token>/', AccessFileView.as_view(), name='access_file'),
    path('me/', UserManagementView.as_view(), name='login'),
    path('upload/', FileUploadView.as_view(), name='upload'),
    path('files/', FileListView.as_view(), name='files'),
    path('mfa/generate-secret/', GenerateMFASecretView.as_view(), name='generate_mfa_secret'),
    path('verify-mfa/', VerifyMFAView.as_view(), name='verify_mfa'),
    path('mfa/enable/', EnableMFAView.as_view(), name='enable_mfa'),
    path('admin/users/', ManageUsersView.as_view(), name='manage_users'),
    path('admin/users/<int:user_id>/', ManageUsersView.as_view(), name='delete_user'),
    path('admin/files/', ManageFilesView.as_view(), name='manage_files'),
    path('admin/files/<int:file_id>/', ManageFilesView.as_view(), name='manage_files'),
    path('files/shared-with-you/', SharedWithYouView.as_view(), name='shared_with_you'),
    path('files/<str:uuid>/download/', DownloadFileView.as_view(), name='download_file'),
]
