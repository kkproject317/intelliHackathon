var app = angular.module("myApp", []);

app.controller("myContent", function($scope, $window) {
    $scope.signIn = function(username, password) {
        let company = null;
        let ifsignIn = false;

        if (username === "INSTABOOK" && password === "Insta@123Secure") {
            ifsignIn = true;
            company = "INSTABOOK";
        } else if (username === "FACEGRAM" && password === "Face@GramPass456") {
            ifsignIn = true;
            company = "FACEGRAM";
        }

        if (ifsignIn) {
            // store in localStorage (persists until browser is closed or cleared)
            localStorage.setItem("ifsignIn", true);
            localStorage.setItem("company", company);

            // redirect to dashboard
            $window.location.href = "dashboard.html";
        } else {
            alert("Invalid username or password");
        }
    };
});
