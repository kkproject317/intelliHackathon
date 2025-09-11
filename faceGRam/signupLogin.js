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

                // Send to backend (uncomment when ready)
                /*
                $http.post("/api/login", payload)
                .then(function(res) {
                    console.log("Login success:", res.data);
                })
                .catch(function(err) {
                    console.error("Login failed:", err);
                });
                */

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