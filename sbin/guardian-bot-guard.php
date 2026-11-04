<?php
/* Guardian PHP request guard. Installed outside the document root by guardian-manager. */
/* GUARDIAN_CONFIG */
if (PHP_SAPI === 'cli' || !isset($guardianConfig) || !is_array($guardianConfig)) {
    return;
}
(static function (array $config) {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    if (is_string($path)) { $path = rawurldecode($path); }
    // Protect only selected expensive PHP entry points; APIs/static content remain unaffected.
    if (!is_string($path) || !preg_match('~(?:^|/)(?:wp-login\.php|xmlrpc\.php|administrator(?:/|$)|login(?:\.php)?(?:/|$))~i', $path)) {
        return;
    }
    $agent = hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    $cookie = (string)($_COOKIE['__Host-guardian_clearance'] ?? '');
    $parts = explode('.', $cookie);
    if (count($parts) === 2 && ctype_digit($parts[0])) {
        $expiry = (int)$parts[0];
        if ($expiry > time() && $expiry <= time() + 1800 &&
            hash_equals(hash_hmac('sha256', $parts[0] . ':' . $agent, $config['signing_key']), $parts[1])) {
            return;
        }
    }
    header('Cache-Control: no-store, private');
    header('X-Robots-Tag: noindex, nofollow');
    if (($_SERVER['HTTPS'] ?? '') !== 'on' && ($_SERVER['HTTPS'] ?? '') !== '1') {
        http_response_code(403);
        exit('Guardian: HTTPS ist fuer die Bot-Pruefung erforderlich.');
    }
    $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
    // Never reflect a protocol-relative URL or control characters into Location.
    if (substr($uri, 0, 1) !== '/' || substr($uri, 0, 2) === '//' || preg_match('/[\x00-\x20\\\\]/', $uri)) {
        $uri = '/';
    }
    $now = time();
    $nonce = bin2hex(random_bytes(16));
    $state = $now . '.' . $nonce . '.' . hash_hmac('sha256', $now . ':' . $nonce . ':' . $uri . ':' . $agent, $config['signing_key']);
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['guardian_turnstile'])) {
        if (!function_exists('curl_init')) {
            http_response_code(503);
            exit('Guardian: PHP-cURL fehlt fuer die Bot-Pruefung.');
        }
        $valid = false;
        $stateParts = explode('.', (string)($_POST['guardian_state'] ?? ''));
        $token = (string)$_POST['guardian_turnstile'];
        if (count($stateParts) === 3 && ctype_digit($stateParts[0]) &&
            (int)$stateParts[0] <= $now && $now - (int)$stateParts[0] <= 300 &&
            preg_match('/^[a-f0-9]{32}$/D', $stateParts[1]) && strlen($token) <= 2048 &&
            hash_equals(hash_hmac('sha256', $stateParts[0] . ':' . $stateParts[1] . ':' . $uri . ':' . $agent, $config['signing_key']), $stateParts[2])) {
            $curl = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
            curl_setopt_array($curl, [CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query(['secret' => $config['secret'], 'response' => $token]),
                CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 8,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
            $raw = curl_exec($curl);
            $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            curl_close($curl);
            $reply = is_string($raw) && strlen($raw) <= 16384 ? json_decode($raw, true) : null;
            $valid = $code === 200 && is_array($reply) && ($reply['success'] ?? false) === true &&
                in_array($reply['hostname'] ?? '', [$config['domain'], 'www.' . $config['domain']], true) &&
                ($reply['action'] ?? '') === 'guardian';
        }
        if ($valid) {
            $expiry = $now + 1800;
            $value = $expiry . '.' . hash_hmac('sha256', $expiry . ':' . $agent, $config['signing_key']);
            setcookie('__Host-guardian_clearance', $value, ['expires' => $expiry, 'path' => '/',
                'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
            header('Location: ' . $uri, true, 303);
            exit;
        }
        http_response_code(403);
    } elseif (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        // Do not silently replay/discard login/API payloads through a challenge form.
        http_response_code(403);
        exit('Guardian: Bitte die Anmeldeseite zuerst im Browser oeffnen und die Bot-Pruefung abschliessen.');
    } else {
        http_response_code(403);
    }
    $esc = static function ($value) { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
    header("Content-Security-Policy: default-src 'none'; script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Guardian Bot-Pruefung</title><body><main><h1>Browser pruefen</h1><p>Bitte bestaetige die Pruefung, um die Anmeldung zu oeffnen.</p><form method="post" action="' . $esc($uri) . '"><input type="hidden" name="guardian_state" value="' . $esc($state) . '"><div class="cf-turnstile" data-sitekey="' . $esc($config['sitekey']) . '" data-action="guardian" data-response-field-name="guardian_turnstile"></div><button type="submit">Weiter</button></form><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></main></body></html>';
    exit;
})($guardianConfig);
unset($guardianConfig);
