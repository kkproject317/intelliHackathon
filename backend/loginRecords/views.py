from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .models import NetLoginRecord
from userDetails.models import UserDetails
from userDetails.serializers import UserLoginSerializer
from .serializers import NetLoginRecordSerializer
from django.contrib.gis.geoip2 import GeoIP2
from geoip2.database import Reader
from django.conf import settings
from django.utils import timezone
import requests
from django.utils.timezone import now, timedelta
from django.db.models import Count
import math
from user_agents import parse
import numpy as np
import joblib

xgb_clf = joblib.load("ml/xgb_model.pkl")
iso = joblib.load("ml/isolation_forest.pkl")
scaler = joblib.load("ml/scaler.pkl")
encoders = joblib.load("ml/encoders.pkl")

categorical_cols = ["company_id", "user_id", "device_id", "asn", "ip_address", "os", "browser"]
numeric_cols = [
    "num_distinct_devices_last30d",
    "failed_attempts_last_10m",
    "hours_since_prev_login",
    "distance_from_prev_login_km",
    "speed_kmh",
    "dist_from_user_login",
    "ip_reputation",
    "ip_vpn_tor",
    "login_success",
    "login_hour",
    "is_weekend"
]
def get_reasons(row):
    reasons = []
    if row.get("speed_kmh", 0) > 1000:
        reasons.append("Impossible travel detected")
    if row.get("ip_vpn_tor") == 1:
        reasons.append("VPN/Tor detected")
    if row.get("ip_reputation", 0) >= 2:
        reasons.append("High-risk IP reputation")
    if row.get("ip_reputation", 0) == 1:
        reasons.append("Medium-risk IP reputation")
    if row.get("failed_attempts_last_10m", 0) > 5 and row.get("login_success") == 0:
        reasons.append("Multiple failed logins in short time")
    if row.get("login_hour") < 6 or row.get("login_hour") > 22:
        reasons.append(f"Login at unusual hour: {row['login_hour']}")
    return "; ".join(reasons) if reasons else "Normal baseline behaviour"


def haversine(lat1, lon1, lat2, lon2):
    """Return distance in km between two lat/lon coords"""
    R = 6371
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

@api_view(['GET'])
def login_Check_Store(request,company_id,user_id,password,device_id):
    data = request.data
    company_id = company_id
    user_id = user_id
    password = password
    device_id = device_id
    # os = data.get("os")
    # browser = data.get("browser")
    # device_type = data.get("device_type")
    #ip address:
    # ip_address = request.META.get("REMOTE_ADDR")
    # ip_address = data.get("ip_address")
    # --- Get IP Address directly ---
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0]
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    if ip_address in ['127.0.0.1', '::1']:
        ip_address = '2402:a00:401:4d9a:a56e:1440:9e76:b8a4'

    # --- Detect OS, Browser, Device Type from User-Agent ---
    user_agent_str = request.META.get('HTTP_USER_AGENT', '')
    user_agent = parse(user_agent_str)

    os = user_agent.os.family + " " + user_agent.os.version_string
    browser = user_agent.browser.family + " " + user_agent.browser.version_string
    if user_agent.is_mobile:
        device_type = "Mobile"
    elif user_agent.is_tablet:
        device_type = "Tablet"
    else:
        device_type = "Laptop"
    login_success = 0  # default = failed
    users = None

    try:
        # First check if user exists
        users = UserDetails.objects.get(user_id=user_id, company=company_id)
        
        # Now validate password
        if users.password == password:
            login_success = 1  # success
        else:
            login_success = 0  # wrong password

    except UserDetails.DoesNotExist:
        users = None
        login_success = 0  # user not found
        return Response(
        {"status": "failed", "message": "User not found", "login_success": 0},
        status=status.HTTP_404_NOT_FOUND
    )
    print(f"DB password: '{users.password}' (type={type(users.password)})")
    print(f"Entered password: '{password}' (type={type(password)})")

    data = {
        "country": None,
        "city": None,
        "asn": None,
        "isp": None,
        "latitude": None,
        "longitude": None,
    }
    try:
        # --- City, Country, Lat/Lon ---
        g = GeoIP2(path=settings.GEOIP_PATH)
        city_info = g.city(ip_address)

        data["country"] = city_info.get("country_name")
        data["city"] = city_info.get("city")
        data["latitude"] = city_info.get("latitude")
        data["longitude"] = city_info.get("longitude")

    except Exception as e:
        print(f"GeoLite2-City lookup failed: {e}")

    try:
        # --- ASN & ISP ---
        asn_db = f"{settings.GEOIP_PATH}/GeoLite2-ASN.mmdb"
        reader_asn = Reader(asn_db)
        asn_info = reader_asn.asn(ip_address)

        data["asn"] = asn_info.autonomous_system_number
        data["isp"] = asn_info.autonomous_system_organization

        reader_asn.close()
    except Exception as e:
        print(f"GeoLite2-ASN lookup failed: {e}")
    
    # --- Step 3: AbuseIPDB Reputation ---
    ip_reputation = 0  # default = normal
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": settings.ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90}

        resp = requests.get(abuse_url, headers=headers, params=params)
        result = resp.json()

        reports = result.get("data", {}).get("totalReports", 0)
        if reports == 0:
            ip_reputation = 0  # normal
        elif reports < 5:
            ip_reputation = 1  # suspicious
        else:
            ip_reputation = 2  # blacklisted
    except Exception as e:
        print(f"AbuseIPDB lookup failed: {e}")
    # --- Step 4: IPQualityScore VPN/TOR Detection ---
    vpn_or_tor = 0
    try:
        ipqs_url = f"https://ipqualityscore.com/api/json/ip/{settings.IPQS_KEY}/{ip_address}"
        resp = requests.get(ipqs_url)
        result = resp.json()

        if result.get("vpn") or result.get("tor"):
            vpn_or_tor = 1
    except Exception as e:
        print(f"IPQS lookup failed: {e}")

    # --- Step 5: Timestamp ---
    timestamp = timezone.now()

    # --- Step 5: Derived features ---
    num_distinct_devices_last30d = 0
    failed_attempts_last_10m = 0
    hours_since_prev_login = None
    distance_from_prev_login_km = None
    speed_kmh = None

    if users:
        # 1) Distinct devices in last 30 days
        last30 = now() - timedelta(days=30)
        num_distinct_devices_last30d = (
            NetLoginRecord.objects.filter(
                user=user_id, company=company_id, timestamp__gte=last30
            ).values("device_id").distinct().count()
        )

        # 2) Failed attempts in last 10 minutes
        last10 = now() - timedelta(minutes=10)
        failed_attempts_last_10m = NetLoginRecord.objects.filter(
            user=user_id, company=company_id, login_success=0, timestamp__gte=last10
        ).count()

        # 3) Get previous login (latest before this attempt)
        prev_login = (
            NetLoginRecord.objects.filter(user=user_id, company=company_id)
            .order_by("-timestamp")
            .first()
        )
        print(prev_login)
        if prev_login:
            # Hours since last login
            delta = now() - prev_login.timestamp
            hours_since_prev_login = delta.total_seconds() / 3600

            # Distance from last login
            if (
                prev_login.latitude and prev_login.longitude
                and data["latitude"] and data["longitude"]
            ):
                distance_from_prev_login_km = haversine(
                    prev_login.latitude, prev_login.longitude,
                    data["latitude"], data["longitude"]
                )

                # Speed = distance / time
                if hours_since_prev_login > 0:
                    speed_kmh = distance_from_prev_login_km / hours_since_prev_login
    
    # --- Distance from HOME ---
    dist_from_home = None
    if getattr(users, "home_lat", None) and getattr(users, "home_long", None):
        if data["latitude"] and data["longitude"]:
            dist_from_home = haversine(
                float(users.home_lat), float(users.home_long),
                data["latitude"], data["longitude"]
            )
    
    features = {
        "company_id": str(company_id).lower(),
        "user_id": str(user_id),
        "device_id": str(device_id),
        "asn": str(data["asn"]),
        "ip_address": str(ip_address),
        "os": os,
        "browser": browser,
        "num_distinct_devices_last30d": num_distinct_devices_last30d,
        "failed_attempts_last_10m": failed_attempts_last_10m,
        "hours_since_prev_login": hours_since_prev_login or 0,
        "distance_from_prev_login_km": distance_from_prev_login_km or 0,
        "speed_kmh": speed_kmh or 0,
        "ip_reputation": ip_reputation,
        "ip_vpn_tor": vpn_or_tor,
        "login_success": login_success,
        "login_hour": timestamp.hour,
        "day_of_week": timestamp.weekday(),
        "is_weekend": 1 if timestamp.weekday() >= 5 else 0,
        "dist_from_user_login" : dist_from_home or 0
    }
    
    # --- Encode categoricals ---
    for col in categorical_cols:
        le = encoders[col]
        val = str(features[col])
        features[col] = le.transform([val])[0] if val in le.classes_ else -1

    # --- Model input ---
    X = np.array([[features[c] for c in categorical_cols + numeric_cols]])
    X_scaled = scaler.transform(X)
    # --- Predictions ---
    prob_xgb = xgb_clf.predict_proba(X)[:, 1]
    iso_scores = -iso.decision_function(X_scaled)
    prob_iso = (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-9)
    risk_score = float((0.5 * prob_xgb + 0.5 * prob_iso) * 1000)
    prediction = int(risk_score >= 50)
    reasons = get_reasons(features)


    # --- Step 6: Save NetLoginRecord ---
    record = NetLoginRecord.objects.create(
        #1
        user=user_id,
        #2
        company=company_id,
        #3
        ip_address=ip_address,
        #4
        country=data["country"],
        #5
        city=data["city"],
        #6
        asn=data["asn"],
        #7
        isp=data["isp"],
        #8
        latitude=data["latitude"],
        #9
        longitude=data["longitude"],
        #10
        device_id=device_id,
        #11
        os=os,
        #12
        browser=browser,
        #13
        device_type=device_type,
        #14
        timestamp=now(),
        #15
        login_success=login_success,
        #16
        ip_reputation=ip_reputation,
        #17
        is_vpn_tor = vpn_or_tor,
        # Derived
        #18
        num_distinct_devices_last30d=num_distinct_devices_last30d,
        #19
        failed_attempts_last_10m=failed_attempts_last_10m,
        #20
        hours_since_prev_login=hours_since_prev_login,
        #21
        distance_from_prev_login_km=distance_from_prev_login_km,
        #22
        speed_kmh=speed_kmh,
        #23
        prediction=prediction,
        #24
        reason=reasons,
        #25
        risk_score=risk_score
    )

    return Response({"status": "success" , "login_success":login_success, "risk_score":risk_score , "prediction": prediction , "reasons": reasons}, status=status.HTTP_200_OK)

@api_view(["GET"])
def getAllLoginRecords(request,company):
    LoginRecords = NetLoginRecord.objects.filter(company=company).order_by('-timestamp')
    if not LoginRecords.exists():
        return Response({"error": f"No records found for company '{company}'"}, status=status.HTTP_404_NOT_FOUND)
    serializer = NetLoginRecordSerializer(LoginRecords, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)