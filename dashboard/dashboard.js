var app = angular.module("myApp",[]);

app.controller("myContent",function($scope,$http,$timeout,$window){
    //apis
    //get api allLoginRecords
    // read values from storage
    $scope.ifsignIn = localStorage.getItem("ifsignIn") === "true";
    $scope.selectedCompany = localStorage.getItem("company")
    // $scope.selectedCompany = 'INSTABOOK'
    // If coming from login page, use persisted company and lock selection
    try {
        var storedCompany = localStorage.getItem('selectedCompany');
        if (storedCompany && typeof storedCompany === 'string') {
            $scope.selectedCompany = storedCompany.toUpperCase();
            $scope.readOnlyCompany = true;
        } else {
            $scope.readOnlyCompany = false;
        }
    } catch(e) { $scope.readOnlyCompany = false; }

    function formatTimeAgo(ts){
        try {
            var ms = toMillis(ts)
            if (ms === null) return '-'
            var date = new Date(ms)
            var diffMs = Date.now() - date.getTime()
            if (isNaN(diffMs)) return '-'
            var sec = Math.floor(diffMs/1000)
            var min = Math.floor(sec/60)
            var hr = Math.floor(min/60)
            var day = Math.floor(hr/24)
            if (sec < 60) return sec + ' sec ago'
            if (min < 60) return min + ' min ago'
            if (hr < 24) return hr + ' hrs ago'
            return day + ' days ago'
        } catch(e){ return '-' }
    }

    function toMillis(ts){
        if (ts == null) return null
        if (typeof ts === 'number') {
            // seconds vs millis
            if (ts < 1e12) return ts * 1000
            return ts
        }
        var parsed = Date.parse(ts)
        if (isNaN(parsed)) return null
        return parsed
    }

    function getRiskLevel(score){
        if (score >= 90) return 'critical'
        if (score >= 70) return 'high'
        if (score >= 50) return 'medium'
        return 'low'
    }

    function computeRiskSummary(records){
        var summary = { critical: 0, high: 0, medium: 0, low: 0 }
        records.forEach(function(r){
            var s = Number(r.risk_score) || 0
            var lvl = getRiskLevel(s)
            summary[lvl] = (summary[lvl] || 0) + 1
        })
        return summary
    }

    function computeRiskyUsers(records){
        return records
            .filter(function(r){ return (Number(r.risk_score) || 0) > 60 })
            .map(function(r){
                var score = Number(r.risk_score) || 0
                return {
                    email: r.user || r.email || '-'
                    , lastActivity: formatTimeAgo(r.timestamp)
                    , tags: Array.isArray(r.reason) ? r.reason : []
                    , riskScore: score
                    , riskLevel: getRiskLevel(score)
                }
            })
            .sort(function(a,b){ return b.riskScore - a.riskScore })
    }

    function computeDeviceDistribution(records){
        var counts = {}
        var total = 0
        records.forEach(function(r){
            var type = (r.device_type || 'Unknown').toString()
            counts[type] = (counts[type] || 0) + 1
            total += 1
        })
        var entries = Object.keys(counts).map(function(k){
            var pct = total ? Math.round((counts[k] / total) * 100) : 0
            return { type: k, value: pct }
        })
        // sort by value desc, cap to top few if desired
        entries.sort(function(a,b){ return b.value - a.value })
        return entries
    }

    function computeSuspiciousDevices(records){
        // Map risky records into suspicious device cards
        return records
            .filter(function(r){ return (Number(r.risk_score) || 0) > 60 })
            .slice(0, 20)
            .map(function(r){
                var risk = getRiskLevel(Number(r.risk_score) || 0)
                // Capitalize risk for display (High/Medium/Critical)
                var riskLabel = risk.charAt(0).toUpperCase() + risk.slice(1)
                return {
                    name: r.device_type || 'Unknown Device'
                    , user: r.user || '-'
                    , location: (r.city ? (r.city + (r.country ? ', ' + r.country : '')) : (r.country || '-'))
                    , risk: riskLabel
                }
            })
    }

    function computeDeviceStats(records){
        var now = Date.now()
        var trusted = 0, blocked = 0, flagged = 0, newToday = 0
        records.forEach(function(r){
            var score = Number(r.risk_score) || 0
            if (score < 30) trusted += 1
            else if (score >= 80) blocked += 1
            else if (score >= 60) flagged += 1
            // new today based on timestamp within last 24h
            var t = toMillis(r.timestamp)
            if (t !== null && (now - t) <= 24*60*60*1000) newToday += 1
        })
        return { trusted: trusted, newToday: newToday, blocked: blocked, flagged: flagged }
    }

    function updateDeviceMetrics(records){
        var safe = Array.isArray(records) ? records : []
        $scope.deviceDistribution = computeDeviceDistribution(safe)
        $scope.suspiciousDevices = computeSuspiciousDevices(safe)
        $scope.deviceStats = computeDeviceStats(safe)
    }

    function computeAlerts(records){
        var critical = 0, high = 0
        records.forEach(function(r){
            var s = Number(r.risk_score) || 0
            if (s >= 90) critical += 1
            else if (s >= 70) high += 1
        })
        return { critical: critical, high: high }
    }

    function computeDevicesSummary(records){
        // Approximate unique devices by signature of device_type+os+browser+user
        var seen = {}
        var seenNew = {}
        var now = Date.now()
        records.forEach(function(r){
            var key = [r.user, r.device_type, r.os, r.browser].filter(Boolean).join('|')
            if (!key) return
            seen[key] = true
            var t = toMillis(r.timestamp)
            if (t !== null && (now - t) <= 24*60*60*1000) seenNew[key] = true
        })
        return { total: Object.keys(seen).length, new: Object.keys(seenNew).length }
    }

    function computeRecentEvents(records){
        var copy = Array.isArray(records) ? records.slice() : []
        copy.sort(function(a,b){ return (toMillis(b.timestamp) || 0) - (toMillis(a.timestamp) || 0) })
        return copy.slice(0,3).map(function(r){
            var ok = !!r.login_success
            return { message: (ok ? '✅' : '❌') + ' ' + (r.user || 'User') + ' ' + (ok ? 'logged in' : 'failed login') + (r.country ? ' ('+r.country+')' : ''), success: ok }
        })
    }

    function computeCompliance(records){
        var total = Array.isArray(records) ? records.length : 0
        if (!total) return { percent: 0, passed: 0, total: 0 }
        var passed = records.reduce(function(acc, r){ return acc + ((Number(r.risk_score) || 0) < 70 ? 1 : 0) }, 0)
        var percent = Math.round((passed/total) * 100)
        return { percent: percent, passed: passed, total: total }
    }

    function computeCompanySummary(records, companyName){
        var totalUsersSet = {}
        var riskSum = 0
        var count = 0
        var anomalies = 0
        records.forEach(function(r){
            if (r.user) totalUsersSet[r.user] = true
            var s = Number(r.risk_score) || 0
            riskSum += s
            count += 1
            if (s > 60) anomalies += 1
        })
        var avgRisk = count ? Math.round(riskSum / count) : 0
        return { name: companyName || '-', riskScore: avgRisk, anomalies: anomalies, users: Object.keys(totalUsersSet).length }
    }

    function computeLoginTile(records){
        var now = Date.now()
        var dayMs = 24*60*60*1000
        var todays = records.filter(function(r){
            var t = toMillis(r.timestamp)
            return t !== null && (now - t) <= dayMs
        })
        var totalLogins = todays.length
        var failedAttempts = todays.filter(function(r){ return !r.login_success }).length
        var blockedEvents = todays.filter(function(r){ return (Number(r.risk_score) || 0) >= 80 }).length
        // preview: if none today, fallback to latest across all records
        var source = todays.length ? todays : records
        var preview = source.slice().sort(function(a,b){ return (toMillis(b.timestamp) || 0) - (toMillis(a.timestamp) || 0) }).slice(0,3)
        return { totalLogins: totalLogins, failedAttempts: failedAttempts, blockedEvents: blockedEvents, preview: preview }
    }

    function updateRiskMetrics(records){
        var safe = Array.isArray(records) ? records : []
        $scope.userRiskSummary = computeRiskSummary(safe)
        $scope.riskyUsers = computeRiskyUsers(safe)
        updateDeviceMetrics(safe)
        // tiles
        $scope.alerts = computeAlerts(safe)
        var dev = computeDevicesSummary(safe)
        $scope.devices = { total: dev.total, new: dev.new }
        $scope.recentEvents = computeRecentEvents(safe)
        $scope.compliance = computeCompliance(safe)
        $scope.topRiskCompany = computeCompanySummary(safe, $scope.selectedCompany)
        // Login Records tile
        var lt = computeLoginTile(safe)
        $scope.loginTile = { total: lt.totalLogins, failed: lt.failedAttempts, blocked: lt.blockedEvents }
        $scope.loginTilePreview = lt.preview
        // map three categories to existing tile binding
        $scope.userRisk = { high: $scope.userRiskSummary.high, medium: $scope.userRiskSummary.medium, low: $scope.userRiskSummary.low }
        // Render charts if analytics view is visible
        if ($scope.showAnalytics) {
            $timeout(function(){ try { renderCharts(safe); } catch(e) { console.warn(e); } }, 0);
        }
    }

    $scope.getLoginRecords = function(companyParam) {
    const selectedCompany = companyParam || $scope.selectedCompany || 'INSTABOOK'; // default company
        return $http.get('http://127.0.0.1:8000/loginRecords/getAllLoginRecords/' + selectedCompany)
        .then(function(response) {
            $scope.loginRecords = response.data;
            $scope.loginData = response.data;
            updateRiskMetrics($scope.loginRecords)
            if ($scope.showGeoMap) { $timeout(function(){ $scope.geoMap(); }, 0); }
            if ($scope.showAnalytics) { $timeout(function(){ try { renderCharts($scope.loginRecords); } catch(e) {} }, 0); }
        })
        .catch(function(error) {
            console.error(error);
        });
        };
        // Call on page load
$scope.getLoginRecords();

    // Re-render charts when data changes and analytics is visible
    $scope.$watchCollection('loginRecords', function(val){
        if ($scope.showAnalytics) {
            $timeout(function(){ try { renderCharts(val || []); } catch(e) {} }, 0);
        }
    });

    $scope.filterDivVar = false
    $scope.filterDiv = function(){
        $scope.filterDivVar = !$scope.filterDivVar
    };
    $scope.closeFilter = function(){
        $scope.filterDivVar = false;
    };
    $scope.showLoginRecords = false
    $scope.showHome = true
    $scope.showAnalytics = false
    $scope.showGeoMap = false
    $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
    $scope.showSecurityPolicies = false
    $scope.openLoginRecords = function(){
        $scope.showLoginRecords = true
        $scope.showHome = false
        $scope.showAnalytics = false
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
    
    $scope.showSecurityPolicies = false
    }
    $scope.home = function(){
        $scope.showLoginRecords = false
        $scope.showHome = true
        $scope.showAnalytics = false
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
    
    $scope.showSecurityPolicies = false
    }
    $scope.analytic = function(){
        $scope.showLoginRecords = false
        $scope.showHome = false
        $scope.showAnalytics = true
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
    
    $scope.showSecurityPolicies = false
        // Ensure DOM has canvases, then render
        $timeout(function(){ try { renderCharts($scope.loginRecords || []); } catch(e) { console.warn(e); } }, 0)
    }
    $scope.geoMap = function(){
        // set view flags so the container exists
        $scope.showLoginRecords = false
        $scope.showHome = false
        $scope.showAnalytics = false
        $scope.showGeoMap = true
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
        
        $scope.showSecurityPolicies = false

        $timeout(function () {
        var container = document.getElementById('geoMap');
        if (!container) return;

        if ($scope.map) {
            $scope.map.remove();
            $scope.map = null;
        }

        $scope.map = L.map('geoMap').setView([20, 0], 2);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo($scope.map);

        function getColor(riskScore) {
            if (riskScore <= 20) return "green";
            if (riskScore <= 50) return "yellow";
            if (riskScore <= 80) return "orange";
            return "red";
        }

        function addMarkers() {
            var loginData = Array.isArray($scope.loginData) && $scope.loginData.length
                ? $scope.loginData
                : (Array.isArray($scope.loginRecords) ? $scope.loginRecords : []);

            if (!Array.isArray(loginData) || loginData.length === 0) {
                console.warn('GeoMap: No login data available to plot');
                return;
            }

            loginData.forEach(function(item) {
                var latRaw = item.latitude || item.lat;
                var lngRaw = item.longitude || item.lng || item.lon || item.long;
                if (latRaw === undefined || lngRaw === undefined) return;

                var lat = parseFloat(latRaw);
                var lng = parseFloat(lngRaw);
                if (isNaN(lat) || isNaN(lng)) return;

                L.circleMarker([lat, lng], {
                    radius: 8,
                    fillColor: getColor(item.risk_score || 0),
                    color: "#000",
                    weight: 1,
                    opacity: 1,
                    fillOpacity: 0.8
                }).bindTooltip(
                    `<b>User:</b> ${item.user || '-'}<br>
                     <b>Company:</b> ${item.company || '-'}<br>
                     <b>City:</b> ${item.city || '-'}, ${item.country || '-'}<br>
                     <b>Risk Score:</b> ${item.risk_score ?? '-'}<br>
                     <b>Prediction:</b> ${item.prediction ?? '-'}<br>
                     <b>Reasons:</b> ${(Array.isArray(item.reason) && item.reason.length) ? item.reason.join(', ') : 'None'}<br>
                     <b>Device:</b> ${[item.device_type, item.os, item.browser].filter(Boolean).join(', ') || '-'}<br>
                     <b>Login Success:</b> ${item.login_success}`
                ).addTo($scope.map);
            });

            // Fix map size issues
            $timeout(function() { 
                if ($scope.map) $scope.map.invalidateSize(); 
            }, 0);
        }

        var hasData = (Array.isArray($scope.loginData) && $scope.loginData.length) || (Array.isArray($scope.loginRecords) && $scope.loginRecords.length);
        if (!hasData) {
            var p = $scope.getLoginRecords && $scope.getLoginRecords();
            if (p && typeof p.then === 'function') {
                p.finally(addMarkers);
            } else {
                // In case getLoginRecords is missing or not a promise, delay slightly and try
                $timeout(addMarkers, 200);
            }
        } else {
            addMarkers();
        }
    }, 0); // run after digest so DOM is present

    }
    $scope.userRiskScoring = function(){
        $scope.showLoginRecords = false
        $scope.showHome = false
        $scope.showAnalytics = false
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = true
    $scope.showDeviceAnalysis = false
    
    $scope.showSecurityPolicies = false
    }
    $scope.deviceAnalysis = function(){
        $scope.showLoginRecords = false
        $scope.showHome = false
        $scope.showAnalytics = false
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = true
    
        $scope.showSecurityPolicies = false
    }
    
    $scope.securityPolices = function(){
        $scope.showLoginRecords = false
        $scope.showHome = false
        $scope.showAnalytics = false
        $scope.showGeoMap = false
        $scope.showUserRiskScoring = false
    $scope.showDeviceAnalysis = false
        
        $scope.showSecurityPolicies = true
    }

    // Mini Geo Map preview on the home tile
    var previewMap = null;
    function initGeoMapPreview(){
        var el = document.getElementById('geoMapPreview');
        if (!el) return;
        if (previewMap) { previewMap.invalidateSize(); return; }
        previewMap = L.map('geoMapPreview', {
            zoomControl: false,
            attributionControl: false,
            dragging: false,
            scrollWheelZoom: false,
            doubleClickZoom: false,
            boxZoom: false,
            keyboard: false,
            tap: false,
            touchZoom: false
        }).setView([20, 0], 1);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(previewMap);
        // simple markers similar to full map
        [[37.7749, -122.4194], [51.5074, -0.1278], [28.6139, 77.2090], [35.6895, 139.6917]].forEach(function(coord){
            L.circleMarker(coord, { radius: 4, color: '#4ecdc4', fillColor: '#4ecdc4', fillOpacity: 0.9, weight: 0 }).addTo(previewMap);
        });
        setTimeout(function(){ previewMap && previewMap.invalidateSize(); }, 0);
    }
    // initialize preview when Home is shown
    $timeout(function(){ if ($scope.showHome) initGeoMapPreview(); }, 0);
    $scope.$watch('showHome', function(v){ if (v) $timeout(initGeoMapPreview, 0); });


    $scope.topRiskCompany = {
    name: "Acme Corp",
    riskScore: 92,
    anomalies: 15,
    users: 240
    };
    // Threat Alerts
$scope.alerts = {
    critical: 12,
    high: 7
};

 // Device Fingerprinting
 $scope.devices = {
     total: 245,
     new: 15
 };

 // Real-time Activity Feed
 $scope.recentEvents = [
     { message: "✅ User A logged in (India)", success: true },
     { message: "❌ User B failed login (USA)", success: false },
     { message: "✅ User C accessed reports (UK)", success: true },
     { message: "❌ User D login attempt blocked (Russia)", success: false }
 ];
 
 // Security Report / Compliance
 $scope.compliance = {
     percent: 92,
     passed: 23,
     total: 25
 };
 
 // Top Riskiest Company (from earlier request)
 $scope.topRiskCompany = {
     name: "Acme Corp",
     riskScore: 92,
     anomalies: 15,
     users: 240
 };
 
 // userRiskSummary and riskyUsers are computed dynamically from loginRecords
 //settings
     $scope.loginPolicies = [
   { name: "Max Failed Attempts", current: "5", status: "Active" },
   { name: "Session Timeout", current: "30 min", status: "Active" },
   { name: "Geo-blocking", current: "Enabled", status: "Active" },
   { name: "Device Verification", current: "Required" }
 ];

 $scope.riskThresholds = [
   { name: "Critical Risk", action: "Block Access", value: 90 },
   { name: "High Risk", action: "Require MFA", value: 70 },
   { name: "Medium Risk", action: "Monitor", value: 50 },
   { name: "Low Risk", action: "Allow", value: 30 }
 ];
 //device analysis is computed dynamically from loginRecords

 $scope.suspiciousDevices = $scope.suspiciousDevices || []
 $scope.deviceDistribution = $scope.deviceDistribution || []
 $scope.deviceStats = $scope.deviceStats || { trusted: 0, newToday: 0, blocked: 0, flagged: 0 }

 
    function renderCharts(records) {
        try {
            // Destroy old charts if they exist
            if (window.loginResultsChart && typeof window.loginResultsChart.destroy === 'function') window.loginResultsChart.destroy();
            if (window.companyRiskChart && typeof window.companyRiskChart.destroy === 'function') window.companyRiskChart.destroy();
            if (window.userRiskChart && typeof window.userRiskChart.destroy === 'function') window.userRiskChart.destroy();
            if (window.deviceChart && typeof window.deviceChart.destroy === 'function') window.deviceChart.destroy();
            if (window.travelChart && typeof window.travelChart.destroy === 'function') window.travelChart.destroy();
            if (window.hourlyActivityChart && typeof window.hourlyActivityChart.destroy === 'function') window.hourlyActivityChart.destroy();
            if (window.osBreakdownChart && typeof window.osBreakdownChart.destroy === 'function') window.osBreakdownChart.destroy();
            if (window.browserBreakdownChart && typeof window.browserBreakdownChart.destroy === 'function') window.browserBreakdownChart.destroy();
            if (window.connectionTypeChart && typeof window.connectionTypeChart.destroy === 'function') window.connectionTypeChart.destroy();
            if (window.ispAnalysisChart && typeof window.ispAnalysisChart.destroy === 'function') window.ispAnalysisChart.destroy();

            var safe = Array.isArray(records) ? records : []

            // Apply a dark theme for all charts once
            if (window.Chart && !window.__chartThemeSet) {
                try {
                    Chart.defaults.color = '#ffffff';
                    Chart.defaults.font.family = 'Montserrat, Arial, sans-serif';
                    Chart.defaults.borderColor = 'rgba(255,255,255,0.15)';
                    Chart.defaults.plugins.legend.labels.color = '#ffffff';
                    window.__chartThemeSet = true;
                } catch(_) {}
            }

            var gridColor = 'rgba(255,255,255,0.12)';
            var tickColor = '#ffffff';

            // 1. Login Results Distribution (Pie)
            var success = safe.filter(function(r){ return !!r.login_success }).length;
            var failed = safe.length - success;
            var lrCtx = document.getElementById("loginResultsChart");
            if (lrCtx) {
                window.loginResultsChart = new Chart(lrCtx, {
                    type: "pie",
                    data: { labels: ["Success", "Failed"], datasets: [{ data: [success, failed], backgroundColor: ["#4CAF50", "#F44336"] }] },
                    options: {
                        plugins: { legend: { labels: { color: tickColor } } }
                    }
                });
            }

            // 2. Company Risk (Bar)
            var companyRisk = {};
            safe.forEach(function(r){
                if (!companyRisk[r.company]) companyRisk[r.company] = [];
                companyRisk[r.company].push(Number(r.risk_score) || 0);
            });
            var companyLabels = Object.keys(companyRisk);
            var avgRisk = companyLabels.map(function(c){
                var arr = companyRisk[c];
                return arr.length ? (arr.reduce(function(a,b){ return a+b; },0)/arr.length) : 0;
            });
            var crCtx = document.getElementById("companyRiskChart");
            if (crCtx) {
                window.companyRiskChart = new Chart(crCtx, {
                    type: "bar",
                    data: { labels: companyLabels, datasets: [{ label: "Avg Risk Score", data: avgRisk, backgroundColor: "#FF9800" }] },
                    options: {
                        plugins: { legend: { labels: { color: tickColor } } },
                        scales: {
                            x: { ticks: { color: tickColor }, grid: { color: gridColor } },
                            y: { beginAtZero: true, max: 100, ticks: { color: tickColor }, grid: { color: gridColor } }
                        }
                    }
                });
            }

            // 3. User Risk Breakdown (Doughnut)
            var low = safe.filter(function(r){ return (Number(r.risk_score)||0) < 30 }).length;
            var medium = safe.filter(function(r){ var s=Number(r.risk_score)||0; return s>=30 && s<60; }).length;
            var high = safe.filter(function(r){ var s=Number(r.risk_score)||0; return s>=60 && s<80; }).length;
            var critical = safe.filter(function(r){ return (Number(r.risk_score)||0) >= 80 }).length;
            var urCtx = document.getElementById("userRiskChart");
            if (urCtx) {
                window.userRiskChart = new Chart(urCtx, {
                    type: "doughnut",
                    data: { labels: ["Low", "Medium", "High", "Critical"], datasets: [{ data: [low, medium, high, critical], backgroundColor: ["#4CAF50", "#FFEB3B", "#FF9800", "#F44336"] }] },
                    options: { plugins: { legend: { labels: { color: tickColor }, position: 'bottom' } } }
                });
            }

            // 4. Device Distribution (Bar)
            var deviceTypes = {};
            safe.forEach(function(r){ deviceTypes[r.device_type] = (deviceTypes[r.device_type] || 0) + 1; });
            var ddCtx = document.getElementById("deviceChart");
            if (ddCtx) {
                window.deviceChart = new Chart(ddCtx, {
                    type: "bar",
                    data: { labels: Object.keys(deviceTypes), datasets: [{ label: "Devices", data: Object.values(deviceTypes), backgroundColor: "#2196F3" }] },
                    options: {
                        plugins: { legend: { labels: { color: tickColor } } },
                        scales: {
                            x: { ticks: { color: tickColor }, grid: { color: gridColor } },
                            y: { ticks: { color: tickColor }, grid: { color: gridColor } }
                        }
                    }
                });
            }

            // 5. Impossible Travel (mocked aggregation)
            var travelCases = {};
            safe.forEach(function(r){
                if (!travelCases[r.user]) travelCases[r.user] = [];
                travelCases[r.user].push(Math.random() * 5000);
            });
            var travelLabels = Object.keys(travelCases);
            var travelData = travelLabels.map(function(u){ return travelCases[u].reduce(function(a,b){ return a+b; },0); });
            var trCtx = document.getElementById("travelChart");
            if (trCtx) {
                window.travelChart = new Chart(trCtx, {
                    type: "bar",
                    data: { labels: travelLabels, datasets: [{ label: "Suspicious Travel Distance (km)", data: travelData, backgroundColor: "#9C27B0" }] },
                    options: {
                        plugins: { legend: { labels: { color: tickColor } } },
                        scales: {
                            x: { ticks: { color: tickColor }, grid: { color: gridColor } },
                            y: { ticks: { color: tickColor }, grid: { color: gridColor } }
                        }
                    }
                });
            }

            // 7. Login Activity by Hour (UTC)
            var hourCounts = new Array(24).fill(0);
            safe.forEach(function(r){ var t = toMillis(r.timestamp); if (t!==null){ var h = new Date(t).getUTCHours(); hourCounts[h]++; }});
            var haCtx = document.getElementById('hourlyActivityChart');
            if (haCtx) {
                window.hourlyActivityChart = new Chart(haCtx, {
                    type: 'line',
                    data: { labels: Array.from({length:24}, function(_,i){ return i+':00'; }), datasets: [{ label:'Logins', data: hourCounts, borderColor:'#4ecdc4', backgroundColor:'#4ecdc433', fill:true, tension:0.35, pointBackgroundColor:'#ffffff', pointBorderColor:'#4ecdc4' }] },
                    options: { plugins:{ legend:{ labels:{ color:tickColor } } }, scales:{ x:{ ticks:{color:tickColor}, grid:{color:gridColor} }, y:{ ticks:{color:tickColor}, grid:{color:gridColor}, beginAtZero:true } } }
                });
            }

            // 8. OS Breakdown (Top)
            var osCounts = {};
            safe.forEach(function(r){ var key = r.os || 'Unknown'; osCounts[key] = (osCounts[key]||0)+1; });
            var osEntries = Object.entries(osCounts).sort(function(a,b){ return b[1]-a[1]; }).slice(0,8);
            var osCtx = document.getElementById('osBreakdownChart');
            if (osCtx) {
                window.osBreakdownChart = new Chart(osCtx, {
                    type: 'bar',
                    data: { labels: osEntries.map(function(e){return e[0]}), datasets: [{ label:'Count', data: osEntries.map(function(e){return e[1]}), backgroundColor:'#00cfff' }] },
                    options: { plugins:{ legend:{ labels:{ color:tickColor } } }, scales:{ x:{ ticks:{color:tickColor}, grid:{color:gridColor} }, y:{ ticks:{color:tickColor}, grid:{color:gridColor}, beginAtZero:true } } }
                });
            }

            // 9. Browser Breakdown (Top)
            var brCounts = {};
            safe.forEach(function(r){ var key = r.browser || 'Unknown'; brCounts[key] = (brCounts[key]||0)+1; });
            var brEntries = Object.entries(brCounts).sort(function(a,b){ return b[1]-a[1]; }).slice(0,8);
            var brCtx = document.getElementById('browserBreakdownChart');
            if (brCtx) {
                window.browserBreakdownChart = new Chart(brCtx, {
                    type: 'bar',
                    data: { labels: brEntries.map(function(e){return e[0]}), datasets: [{ label:'Count', data: brEntries.map(function(e){return e[1]}), backgroundColor:'#ff9f43' }] },
                    options: { plugins:{ legend:{ labels:{ color:tickColor } } }, scales:{ x:{ ticks:{color:tickColor}, grid:{color:gridColor} }, y:{ ticks:{color:tickColor}, grid:{color:gridColor}, beginAtZero:true } } }
                });
            }

            // 10. Connection Type (Direct vs VPN/Tor; proxy if provided by is_proxy)
            var vpnCount = safe.filter(function(r){ return !!r.is_vpn_tor; }).length;
            var directCount = safe.length - vpnCount;
            var ctCtx = document.getElementById('connectionTypeChart');
            if (ctCtx) {
                window.connectionTypeChart = new Chart(ctCtx, {
                    type: 'pie',
                    data: { labels:['Direct','VPN/Tor'], datasets:[{ data:[directCount, vpnCount], backgroundColor:['#2ecc71','#e74c3c'] }] },
                    options: { plugins:{ legend:{ position:'bottom', labels:{ color:tickColor } } } }
                });
            }

            // 11. ISP / ASN Analysis (Top 10 by risky share)
            var ispAgg = {};
            safe.forEach(function(r){
                var isp = r.isp || 'Unknown';
                if (!ispAgg[isp]) ispAgg[isp] = { total:0, risky:0 };
                ispAgg[isp].total++;
                if ((Number(r.risk_score)||0) > 70) ispAgg[isp].risky++;
            });
            var ispRows = Object.keys(ispAgg).map(function(k){
                var v = ispAgg[k];
                return { isp:k, pct: v.total ? (v.risky/v.total*100) : 0 };
            }).sort(function(a,b){ return b.pct - a.pct; }).slice(0,10);
            var ispCtx = document.getElementById('ispAnalysisChart');
            if (ispCtx) {
                window.ispAnalysisChart = new Chart(ispCtx, {
                    type: 'bar',
                    data: { labels: ispRows.map(function(r){return r.isp}), datasets:[{ label:'% Risky', data: ispRows.map(function(r){return Math.round(r.pct)}), backgroundColor:'#f44336' }] },
                    options: { plugins:{ legend:{ labels:{ color:tickColor } } }, scales:{ x:{ ticks:{color:tickColor}, grid:{color:gridColor} }, y:{ ticks:{color:tickColor}, grid:{color:gridColor}, beginAtZero:true, max:100 } } }
                });
            }
        } catch(e) { console.warn('renderCharts error', e); }
    }
 
   //apis to call
   // all login records
   // all companies
   //all company records
   //geo map
   //lat longs

   //risk scoring
   //userId (currect time - timestamp) avg risk score reason

   //Company records
   //company name   total users of company   company avg risk score to percent status(decide from data in frontend)

   //device analysis


});