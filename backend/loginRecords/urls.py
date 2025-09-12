from django.urls import path
from .views import login_Check_Store,getAllLoginRecords

urlpatterns = [
    path("postLoginRecord/<str:company_id>/<str:user_id>/<str:password>/<str:device_id>",login_Check_Store,name="postLoginRecord"),
    path("getAllLoginRecords/<str:company>",getAllLoginRecords,name="getAllLoginRecords")
]