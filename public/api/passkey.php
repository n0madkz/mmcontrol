<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function start_passkey_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'cookie_secure' => $secure,
    ]);
}

function b64url_encode(string $value): string {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function b64url_decode(string $value): string {
    $value = strtr($value, '-_', '+/');
    $padding = strlen($value) % 4;
    if ($padding !== 0) $value .= str_repeat('=', 4 - $padding);
    $decoded = base64_decode($value, true);
    if ($decoded === false) respond(['error' => 'Invalid passkey data'], 400);
    return $decoded;
}

function binary_value(mixed $value): string {
    if (is_string($value)) return $value;
    if (is_object($value) && method_exists($value, 'getBinaryString')) return $value->getBinaryString();
    respond(['error' => 'Invalid passkey response'], 400);
}

function passkey_service(): \lbuchs\WebAuthn\WebAuthn {
    $siteRoot = dirname(__DIR__);
    $autoloadPaths = [
        $siteRoot . '/vendor/autoload.php',
        // Supports Plesk deployments that copy public/ into httpdocs while Composer runs in public/.
        $siteRoot . '/public/vendor/autoload.php',
    ];
    $autoload = null;
    foreach ($autoloadPaths as $path) {
        if (is_file($path)) {
            $autoload = $path;
            break;
        }
    }
    if ($autoload === null) {
        respond(['error' => 'Face ID is not configured on the server yet'], 503);
    }
    require_once $autoload;
    $config = app_config();
    $rpId = (string)($config['rp_id'] ?? '');
    if ($rpId === '' || !preg_match('/^[a-z0-9.-]+$/i', $rpId)) {
        respond(['error' => 'Invalid Face ID domain configuration'], 503);
    }

    return new \lbuchs\WebAuthn\WebAuthn('MM Control', strtolower($rpId), ['none']);
}

function public_key_options(object $options): array {
    $data = json_decode(json_encode($options, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data)) respond(['error' => 'Invalid passkey options'], 500);
    return $data['publicKey'] ?? $data;
}

function passkey_credentials(PDO $pdo, ?int $userId = null): array {
    $sql = 'SELECT id, user_id, credential_id, credential_public_key, signature_counter FROM mm_passkeys';
    if ($userId === null) return $pdo->query($sql)->fetchAll();
    $query = $pdo->prepare($sql . ' WHERE user_id = ?');
    $query->execute([$userId]);
    return $query->fetchAll();
}

function save_challenge(string $name, string $challenge, ?int $userId = null): void {
    $_SESSION[$name] = [
        'challenge' => b64url_encode($challenge),
        'user_id' => $userId,
        'created_at' => time(),
    ];
}

function load_challenge(string $name, ?int $userId = null): string {
    $data = $_SESSION[$name] ?? null;
    unset($_SESSION[$name]);
    if (!is_array($data) || !isset($data['challenge'], $data['created_at'])
        || (time() - (int)$data['created_at']) > 300
        || ($userId !== null && (int)($data['user_id'] ?? 0) !== $userId)) {
        respond(['error' => 'Face ID request expired. Please try again.'], 400);
    }
    return b64url_decode((string)$data['challenge']);
}

function response_value(array $input, string $name): string {
    $value = $input['response'][$name] ?? null;
    if (!is_string($value) || $value === '') respond(['error' => 'Incomplete Face ID response'], 400);
    return b64url_decode($value);
}

start_passkey_session();
$pdo = database();
$action = (string)($_GET['action'] ?? 'status');

try {
    if ($action === 'status') {
        passkey_service();
        $count = (int)$pdo->query('SELECT COUNT(*) FROM mm_passkeys')->fetchColumn();
        respond(['available' => $count > 0, 'backend' => 'php-passkeys-v2']);
    }

    if ($action === 'register-options') {
        $user = require_user($pdo);
        $input = input_json();
        $credentials = passkey_credentials($pdo, (int)$user['id']);
        $excluded = array_map(static fn(array $credential): string => b64url_decode($credential['credential_id']), $credentials);
        $webAuthn = passkey_service();
        $options = $webAuthn->getCreateArgs(
            pack('N', (int)$user['id']),
            $user['username'],
            (string)($input['username'] ?? $user['username']),
            240,
            true,
            true,
            false,
            $excluded
        );
        save_challenge('mm_passkey_register', binary_value($webAuthn->getChallenge()), (int)$user['id']);
        respond(public_key_options($options));
    }

    if ($action === 'register-verify') {
        $user = require_user($pdo);
        $input = input_json();
        $challenge = load_challenge('mm_passkey_register', (int)$user['id']);
        $webAuthn = passkey_service();
        $credential = $webAuthn->processCreate(
            response_value($input, 'clientDataJSON'),
            response_value($input, 'attestationObject'),
            $challenge,
            true,
            true,
            false
        );
        $credentialId = b64url_encode(binary_value($credential->credentialId));
        $transports = $input['response']['transports'] ?? [];
        if (!is_array($transports)) $transports = [];
        $query = $pdo->prepare('INSERT INTO mm_passkeys (user_id, credential_id, credential_public_key, signature_counter, transports) VALUES (?, ?, ?, ?, ?)');
        $query->execute([
            (int)$user['id'],
            $credentialId,
            (string)$credential->credentialPublicKey,
            max(0, (int)($credential->signatureCounter ?? 0)),
            json_encode(array_values($transports), JSON_THROW_ON_ERROR),
        ]);
        respond(['verified' => true]);
    }

    if ($action === 'auth-options') {
        $credentials = passkey_credentials($pdo);
        if (!$credentials) respond(['error' => 'Face ID is not connected'], 400);
        $credentialIds = array_map(static fn(array $credential): string => b64url_decode($credential['credential_id']), $credentials);
        $webAuthn = passkey_service();
        $options = $webAuthn->getGetArgs($credentialIds, 240, false, false, false, true, true, true);
        save_challenge('mm_passkey_auth', binary_value($webAuthn->getChallenge()));
        respond(public_key_options($options));
    }

    if ($action === 'auth-verify') {
        $input = input_json();
        $challenge = load_challenge('mm_passkey_auth');
        $rawId = $input['rawId'] ?? $input['id'] ?? null;
        if (!is_string($rawId) || $rawId === '') respond(['error' => 'Missing Face ID credential'], 400);
        $credentialId = b64url_encode(b64url_decode($rawId));
        $query = $pdo->prepare('SELECT id, user_id, credential_public_key, signature_counter FROM mm_passkeys WHERE credential_id = ?');
        $query->execute([$credentialId]);
        $passkey = $query->fetch();
        if (!$passkey) respond(['error' => 'Face ID credential not found'], 401);

        $webAuthn = passkey_service();
        $verified = $webAuthn->processGet(
            response_value($input, 'clientDataJSON'),
            response_value($input, 'authenticatorData'),
            response_value($input, 'signature'),
            $passkey['credential_public_key'],
            $challenge,
            (int)$passkey['signature_counter'],
            true,
            true
        );
        if ($verified !== true) respond(['error' => 'Face ID verification failed'], 401);
        $counter = method_exists($webAuthn, 'getSignatureCounter') ? $webAuthn->getSignatureCounter() : null;
        if (is_int($counter) && $counter > (int)$passkey['signature_counter']) {
            $pdo->prepare('UPDATE mm_passkeys SET signature_counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?')->execute([$counter, $passkey['id']]);
        } else {
            $pdo->prepare('UPDATE mm_passkeys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?')->execute([$passkey['id']]);
        }
        respond(['verified' => true, 'token' => issue_token($pdo, (int)$passkey['user_id'])]);
    }

    respond(['error' => 'Unknown Face ID action'], 404);
} catch (Throwable) {
    respond(['error' => 'Face ID verification failed. Please try again.'], 400);
}
