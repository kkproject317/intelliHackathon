import uuid
from django.db import models
from django.utils import timezone

class NetLoginRecord(models.Model):
    # Primary key
    login_id = models.BigAutoField(primary_key=True)
    company = models.CharField(max_length=128)
    user = models.CharField(max_length=128)
    # Raw / geo / network fields
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    country = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    city = models.CharField(max_length=150, blank=True, null=True)
    asn = models.CharField(max_length=50, blank=True, null=True)       # store as string to support 'AS12345' or numbers
    isp = models.CharField(max_length=255, blank=True, null=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, default = 23.076099) 
    longitude = models.DecimalField(max_digits=9, decimal_places=6, default = 72.508408)
    device_id = models.CharField(max_length=255, db_index=True)    
    os = models.CharField(max_length=100, blank=True, null=True)
    browser = models.CharField(max_length=100, blank=True, null=True)
    DEVICE_TYPE_CHOICES = [
        ("desktop", "Desktop"),
        ("mobile", "Mobile"),
        ("tablet", "Tablet"),
        ("bot", "Bot"),
    ]

    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        blank=True,
        null=True,
        db_index=True
    )
    timestamp = models.DateTimeField(db_index=True)           # actual login event time (UTC) 
    login_success = models.BooleanField(default=False, db_index=True)
    IP_REPUTATION_CHOICES = [
        ("0", "normal"),
        ("1", "suspicious"),
        ("2", "blacklisted"),
    ]
    ip_reputation = models.CharField(max_length=2, choices=IP_REPUTATION_CHOICES, default="0", db_index=True)
    is_vpn_tor = models.BooleanField(default=False, db_index=True)
    num_distinct_devices_last30d = models.PositiveIntegerField(default=0)
    failed_attempts_last_10m = models.PositiveIntegerField(default=0)
    hours_since_prev_login = models.FloatField(null=True, blank=True)
    distance_from_prev_login_km = models.FloatField(null=True, blank=True)
    speed_kmh = models.FloatField(null=True, blank=True) 

    # ML model outputs
    PREDICTION_CHOICES = [
        ("normal", "normal"),
        ("anomalous", "anomalous"),
    ]
    prediction = models.CharField(max_length=20, choices=PREDICTION_CHOICES, default="normal", db_index=True)
    risk_score = models.FloatField(null=True, blank=True)  # 0.0 - 1.0
    # Use JSONField to store flexible 'reason' list or structured explanation
    reason = models.JSONField(null=True, blank=True, help_text="List of reasons / contributing features (e.g., ['New device','Geo mismatch'])")
