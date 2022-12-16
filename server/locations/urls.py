
from django.urls import path
from locations.views import newLocation, viewLoc

app_name = 'locations'
urlpatterns = [
    path('', viewLoc, name="viewLoc"),
    path('addlocation/', newLocation, name='newLocation'),
    # path('<int:locationNo>/',)
]
