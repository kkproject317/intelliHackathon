from rest_framework import serializers
from .models import NetLoginRecord

class NetLoginRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetLoginRecord
        fields = "__all__"