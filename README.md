# Team - CobraOS
-----------------------------

#Team Members
Krisha Shah – Nirma University – krishabr2007@gmail.com [Team head]
Krina Shah – Nirma University – krinabr2007@gmail.com
Anshul Patel – Nirma University – anshul2266patel@gmail.com


#Objective
With the rise of remote work and cloud services, stolen credentials pose a significant security risk. Attackers often log in from unusual locations, devices, or times, which traditional systems fail to detect. Our solution leverages AI/ML to detect anomalous logins and prevent account takeovers, helping secure sensitive data for enterprises and financial institutions.

#Problem Statement
Traditional security systems often miss subtle anomalies in login behavior, leading to account takeovers.

#Solution
Our system is an intelligent security solution that leverages AI/ML to detect and prevent account takeovers by analyzing login behavior patterns and detects suspicious logins using:
    Geo-location analysis
    Device fingerprinting
    Login time patterns
    Network anomalies (IP reputation, ASN, ISP checks)
    User-behavioral modeling (pattern recognition of normal activity)
    Brute force login detection (multiple failed attempts)
Output: Risk Score (0-100) + Prediction (normal/anomalous) + Reasons

#Users
    IT Security Teams
    Cloud Security Analysts
    End-users (real-time protection)

#Expected Outcomes
    An AI/ML model that identifies suspicious logins without disrupting legitimate users.
    A real-time detection system to flag or challenge anomalous logins.

#Potential Impact
    Prevent credential theft and account takeover.
    Improve enterprise and financial data security.
    Reduce fraud risks for BFSI and IT enterprises.
    
#Tech Stack
Frontend
    HTML, CSS, AngularJS, FingerprintJS (Device fingerprinting), Chart.js (Data visualization)
Backend
    Django REST Framework, MySQL Client, External APIs(AbuseIPDB, IPQualityScore (Proxy/VPN detection)), GeoIP2 db.
Machine Learning Model
    XGBoost Classifier (Supervised), Isolation Forest (Unsupervised), Ensemble Scoring (Weighted risk scoring)
Libraries
    pandas, numpy, scikit-learn, xgboost

#Setup & Installation
1️⃣ Clone the Repository
    First, download the project from the repository and move into the project folder.
2️⃣ Backend Setup (Django + MySQL)
    - Create and activate virtual environment:
        python3 -m venv venv
        source venv/bin/activate   # Linux/Mac
        venv\Scripts\activate      # Windows
    - Install dependencies:
        pip install -r requirements.txt
    - Configure MySQL database in settings.py:
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.mysql',
                'NAME': '<db_name>',
                'USER': '<db_user>',
                'PASSWORD': '<db_password>',
                'HOST': 'localhost',
                'PORT': '3306',
            }
        }
    - Apply migrations & run server:
        python manage.py migrate
        python manage.py runserver
3️⃣ Frontend Setup (AngularJS + Chart.js + FingerprintJS)
    - Navigate to the frontend folder inside the project.
    - Install the necessary frontend libraries (AngularJS, Chart.js, FingerprintJS). (but using weblinks to all three js)
4️⃣ Machine Learning Model Setup
    - Ensure the required Python libraries (pandas, numpy, scikit-learn, xgboost) are installed.
    - If training scripts are included, run the training step to generate the model.
    - If the ML model is served separately (e.g., as a Flask or Django API service), start that service so it can interact with the backend.
    - Ensure Python libraries are installed:
        pip install pandas numpy scikit-learn xgboost
5️⃣ Integration
    - The frontend interacts with the Django backend APIs to fetch and display data.
    - The backend integrates with external APIs (AbuseIPDB, IPQualityScore) for IP and proxy detection.
    - The ML model is embedded into the backend pipeline to provide risk scoring for login attempts.

#ML Model Architecture
Input Layer (Features)
├── Geo-location vectors (latitude, longitude, country)
├── Device fingerprints (browser, OS, screen resolution)
├── Temporal patterns (login time, frequency)
├── Network indicators (IP reputation, ASN, ISP)
└── Behavioral metrics (typing patterns, navigation)

Ensemble Model
├── XGBoost Classifier (50% weight) - Supervised learning
└── Isolation Forest (50% weight) - Unsupervised anomaly detection

Output: Risk Score (0-100) + Prediction (normal/anomalous) + Reasons

#Usage Instructions
For Security Analysts
    Dashboard Access: Navigate to http://localhost:8000/dashboard
    Monitor Logins: View real-time login attempts and risk scores
    Configure Rules: Set custom thresholds and response actions

For End Users
    Normal Login: Standard login process with invisible security checks
    Challenge Response: Additional verification for suspicious attempts
    
#🎬 Demo Video
Watch Demo Video - attached in repo 
    Live demonstration of anomaly detection
    Dashboard walkthrough and feature showcase
    Real-time risk scoring in action
    
#Current Limitations & Future Enhancements
- Known Limitations
    Requires initial training period (7-14 days) for user behavior baseline
    Performance may vary with limited historical data for new users
    External API dependencies for IP reputation checks

- Planned Improvements
    Mobile App: Native iOS/Android applications
    Advanced Biometrics: Keystroke dynamics and mouse movement patterns
    Federated Learning: Privacy-preserving model updates across organizations
    Integration Suite: Pre-built connectors for popular enterprise systems



