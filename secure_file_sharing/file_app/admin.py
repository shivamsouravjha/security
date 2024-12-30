from django.contrib import admin
from .models import User, File

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role')

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ('file', 'owner', 'encrypted', 'created_at')
