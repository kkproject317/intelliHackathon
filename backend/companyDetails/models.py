import uuid
from django.db import models
from django.utils import timezone


class CompanyDetails(models.Model):
    company_id = models.CharField(max_length=100, primary_key=True)
    company_name = models.CharField(max_length=255)
    industry = models.CharField(max_length=100, blank=True, null=True)
    password = models.CharField(max_length=255)
    company_risk_score = models.FloatField(null=True, blank=True)