from django.contrib import admin
from .models import Asset, Vulnerability

# Register your models here.
admin.site.register(Asset)
admin.site.register(Vulnerability)
