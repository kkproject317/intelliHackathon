from rest_framework import serializers

class UserLoginSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=128)
    password = serializers.CharField(write_only=True)
    company_id = serializers.CharField(max_length=128)
    ip_address = serializers.IPAddressField(required=False, allow_null=True)
    device_id = serializers.CharField(max_length=255, required=False, allow_blank=True)
    os = serializers.CharField(max_length=100, required=False, allow_blank=True)
    browser = serializers.CharField(max_length=100, required=False, allow_blank=True)
    DEVICE_TYPE_CHOICES = [
        ("desktop", "Desktop"),
        ("mobile", "Mobile"),
        ("tablet", "Tablet"),
        ("bot", "Bot"),
    ]

    device_type = serializers.ChoiceField(
        choices=DEVICE_TYPE_CHOICES,
        required=False,
        allow_null=True
    )

