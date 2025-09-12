// Define AngularJS module
var app = angular.module('myApp', []);

// Define controller
app.controller("myContent", function($scope, $http) {
    $scope.companyName = "FACEGRAM";

    // Load fingerprint agent when controller initializes
    var fpPromise = null;
    
    // Initialize FingerprintJS
    if (typeof FingerprintJS !== 'undefined') {
        fpPromise = FingerprintJS.load();
    }

    $scope.signIn = function(username, password) {
        if (!username || !password) {
            alert('Please enter both username and password');
            return;
        }

        // If FingerprintJS is available, get fingerprint
        if (fpPromise) {
            fpPromise.then(function(fp) {
                return fp.get();
            }).then(function(result) {
                var payload = {
                    company_name: $scope.companyName,
                    user_id: username,
                    password: password,
                    deviceId: result.visitorId // Using fingerprint as device ID
                };

                console.log("Payload to send:", payload);
                console.log("Device fingerprint:", result.visitorId);

                return $http.get("http://127.0.0.1:8000/postLoginRecord/" +
                encodeURIComponent($scope.companyName) + "/" +
                encodeURIComponent(username) + "/" +
                encodeURIComponent(password) + "/" +
                encodeURIComponent(result.visitorId))
                .then(function(response){
                    console.log(response.data);
                    if(response.data.login_success == 1){
                        if(response.data.risk_score < 30){
                            $scope.risk = "no risk"
                        }
                        else if(response.data.risk_score >= 30 && response.data.risk_score <60){
                            $scope.risk = "medium risk"
                        }
                        else if(response.data.risk_score >= 60 && response.data.risk_score <80){
                            $scope.risk = "high risk"
                        }
                        else if(response.data.risk_score >= 80 && response.data.risk_score <= 100){
                            $scope.risk = "critical risk"
                        }
                        $scope.message = response.data.prediction + " login with " + $scope.risk;
                        alert($scope.message);
                    }else{
                        alert("Incorrect password or username");
                    }
                }).catch(function(error){
                    console.error(error);
                });
                


                // Clear fields
                $scope.username = "";
                $scope.password = "";
            }).catch(function(error) {
                console.error("Fingerprint generation failed:", error);
                
                // Fallback without fingerprint
                var payload = {
                    company_name: $scope.companyName,
                    user_id: username,
                    password: password
                };

                console.log("Payload to send (no fingerprint):", payload);

                // Clear fields
                $scope.username = "";
                $scope.password = "";
            });
        } else {
            // FingerprintJS not available, proceed without it
            var payload = {
                company_name: $scope.companyName,
                user_id: username,
                password: password
            };

            console.log("Payload to send (FingerprintJS not loaded):", payload);

            // Clear fields
            $scope.username = "";
            $scope.password = "";
        }
    };
});