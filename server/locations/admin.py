from django.contrib import admin
from .models import Location

# Register your models here.


class LocationAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)


admin.site.register(Location, LocationAdmin)
