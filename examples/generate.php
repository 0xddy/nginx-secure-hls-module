<?php
require_once __DIR__ . '/sign.php';

function generate($allow, $url)
{
    if (!$url) {
        return '';
    }

    $url = str_replace('https://origin.example.com:4433', 'https://media.example.com', $url);
    $ip = (string) hy_get_user_ip();
    $userid = (string) current_id();
    $time = (string) time();

    // Must match secure_hls_hmac_key in the nginx configuration.
    $secret = getenv('HLS_SECRET');
    if ($secret === false) {
        $secret = 'demo-hls-secret';
    }

    // $allow is retained for compatibility with the existing call sites.
    return hls_signed_url($url, $userid, $ip, $time, $secret);
}
