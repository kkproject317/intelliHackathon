import uuid
from django.db import models
from django.utils import timezone

class UserDetails(models.Model):
    user_id = models.CharField(max_length=128) 
    company = models.CharField(max_length=128)
    email = models.EmailField(max_length=255, blank=True, null=True, db_index=True)
    username = models.CharField(max_length=150, blank=True, null=True)
    home_country = models.CharField(max_length=100, blank=True, null=True)
    home_city = models.CharField(max_length=100, blank=True, null=True)
    home_lat = models.DecimalField(max_digits=9, decimal_places=6, default = 23.076099) 
    home_long = models.DecimalField(max_digits=9, decimal_places=6, default = 72.508408)
    default_device_id = models.CharField(max_length=255, blank=True, null=True)
    password = models.CharField(max_length=255)
    risk_Score = models.FloatField(null=True, blank=True)