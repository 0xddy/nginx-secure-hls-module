<?php
// php examples/sign.php 'https://example.com/upload/hls/video/hls.m3u8' 1 [IP] [UNIX_SECONDS]
// HLS_SECRET must match secure_hls_hmac_key in auth.conf.
// Paths are normalized as Linux nginx with merge_slashes on (the default).
function hls_normalize_path(string $path): string
{
    if ($path === '' || $path[0] !== '/' || preg_match('/%(?![0-9a-fA-F]{2})/', $path)) {
        throw new InvalidArgumentException('Invalid absolute URL path');
    }
    $decoded = rawurldecode($path);
    if (preg_match('/[\x00-\x1f\x7f\\\\]/', $decoded)) {
        throw new InvalidArgumentException('Control characters/backslashes are not allowed in paths');
    }
    $trailing = str_ends_with($decoded, '/') || preg_match('~/\.{1,2}$~', $decoded);
    $segments = [];
    foreach (explode('/', $decoded) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            if (!$segments) {
                throw new InvalidArgumentException('Path escapes the URL root');
            }
            array_pop($segments);
        } else {
            $segments[] = $part;
        }
    }
    $normalized = '/' . implode('/', $segments);
    return $trailing && $normalized !== '/' ? $normalized . '/' : $normalized;
}

function hls_signed_url(string $url, string $user, string $ip, string $time, string $secret): string
{
    if ($user === '' || $secret === '' || !preg_match('/^[0-9]+$/D', $time)
        || preg_match('/[\x00-\x1f\x7f]/', $user . $ip . $url)) {
        throw new InvalidArgumentException('Invalid user, time, URL or empty key');
    }
    $parts = parse_url($url);
    if ($parts === false || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
        || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)) {
        throw new InvalidArgumentException('An absolute HTTP(S) URL without userinfo is required');
    }
    $path = hls_normalize_path($parts['path'] ?? '/');
    $token = hash_hmac('sha256', $user . "\n" . $time . "\n" . $path, $secret);
    // Replace auth fields; preserve business query bytes and ordering.
    $query = [];
    foreach (explode('&', $parts['query'] ?? '') as $field) {
        if ($field === '') {
            continue;
        }
        $name = urldecode(explode('=', $field, 2)[0]);
        if (!in_array($name, ['token', 'ukey', 'pkey', 't'], true)) {
            $query[] = $field;
        }
    }
    $params = ['token' => $token, 'ukey' => $user, 't' => $time];
    if ($ip !== '') {
        $params['pkey'] = $ip;
    }
    $query[] = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    $authority = strtolower($parts['scheme']) . '://' . $parts['host'];
    if (isset($parts['port'])) {
        $authority .= ':' . $parts['port'];
    }
    $encodedPath = str_replace('%2F', '/', rawurlencode($path));
    return $authority . $encodedPath . '?' . implode('&', $query)
        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    if (empty($argv[1])) {
        fwrite(STDERR, "Usage: php sign.php URL USER_ID [IP] [UNIX_SECONDS]\n");
        exit(2);
    }
    try {
        $secret = getenv('HLS_SECRET');
        echo hls_signed_url($argv[1], $argv[2] ?? '1', $argv[3] ?? '',
            $argv[4] ?? (string) time(), $secret === false ? 'demo-hls-secret' : $secret) . PHP_EOL;
    } catch (InvalidArgumentException $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL);
        exit(2);
    }
}
