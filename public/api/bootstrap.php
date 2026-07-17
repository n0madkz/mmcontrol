<?php
declare(strict_types=1);

function respond(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function input_json(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') return [];
    $data = json_decode($raw, true);
    if (!is_array($data)) respond(['error' => 'Invalid JSON'], 400);
    return $data;
}

function app_config(): array {
    static $config = null;
    if (is_array($config)) return $config;
    $configPath = __DIR__ . '/config.php';
    if (!is_file($configPath)) respond(['error' => 'Server database is not configured'], 503);
    $config = require $configPath;
    if (!is_array($config) || !isset($config['dsn'], $config['user'], $config['password'])) {
        respond(['error' => 'Invalid database configuration'], 503);
    }
    return $config;
}

function database(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $config = app_config();

    try {
        $pdo = new PDO($config['dsn'], $config['user'], $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        ensure_schema($pdo);
        return $pdo;
    } catch (Throwable) {
        respond(['error' => 'Database connection failed'], 503);
    }
}

function ensure_schema(PDO $pdo): void {
    $pdo->exec('CREATE TABLE IF NOT EXISTS mm_users (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(120) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS mm_sessions (
        token CHAR(64) PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT mm_sessions_user_fk FOREIGN KEY (user_id) REFERENCES mm_users(id) ON DELETE CASCADE,
        INDEX mm_sessions_expiry_idx (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS mm_app_state (
        user_id INT UNSIGNED PRIMARY KEY,
        data LONGTEXT NOT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT mm_app_state_user_fk FOREIGN KEY (user_id) REFERENCES mm_users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS mm_passkeys (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        credential_id VARCHAR(1024) NOT NULL UNIQUE,
        credential_public_key MEDIUMTEXT NOT NULL,
        signature_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
        transports JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP NULL DEFAULT NULL,
        CONSTRAINT mm_passkeys_user_fk FOREIGN KEY (user_id) REFERENCES mm_users(id) ON DELETE CASCADE,
        INDEX mm_passkeys_user_idx (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
}

function bearer_token(): string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    return preg_match('/^Bearer\\s+(.+)$/i', $header, $match) ? trim($match[1]) : '';
}

function user_from_token(PDO $pdo): ?array {
    $token = bearer_token();
    if ($token === '' || !preg_match('/^[a-f0-9]{64}$/', $token)) return null;
    $query = $pdo->prepare('SELECT u.id, u.username FROM mm_sessions s JOIN mm_users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > UTC_TIMESTAMP()');
    $query->execute([$token]);
    return $query->fetch() ?: null;
}

function require_user(PDO $pdo): array {
    $user = user_from_token($pdo);
    if (!$user) respond(['error' => 'Unauthorized'], 401);
    return $user;
}

function issue_token(PDO $pdo, int $userId): string {
    $pdo->prepare('DELETE FROM mm_sessions WHERE expires_at <= UTC_TIMESTAMP()')->execute();
    $token = bin2hex(random_bytes(32));
    $pdo->prepare('INSERT INTO mm_sessions (token, user_id, expires_at) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))')->execute([$token, $userId]);
    return $token;
}
