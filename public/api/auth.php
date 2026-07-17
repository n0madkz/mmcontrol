<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$pdo = database();
$action = (string)($_GET['action'] ?? '');
$owner = $pdo->query('SELECT id, username, password_hash FROM mm_users ORDER BY id LIMIT 1')->fetch();

if ($action === 'status' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    respond(['configured' => (bool)$owner, 'user' => $owner['username'] ?? null]);
}

if ($action === 'setup' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($owner) respond(['error' => 'Owner already exists'], 409);
    $input = input_json();
    $user = trim((string)($input['user'] ?? ''));
    $hash = (string)($input['hash'] ?? '');
    if ($user === '' || strlen($user) > 120 || !preg_match('/^[a-f0-9]{8,128}$/', $hash)) respond(['error' => 'Invalid credentials'], 400);
    $query = $pdo->prepare('INSERT INTO mm_users (username, password_hash) VALUES (?, ?)');
    $query->execute([$user, password_hash($hash, PASSWORD_DEFAULT)]);
    $id = (int)$pdo->lastInsertId();
    respond(['user' => $user, 'token' => issue_token($pdo, $id)]);
}

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = input_json();
    $user = trim((string)($input['user'] ?? ''));
    $hash = (string)($input['hash'] ?? '');
    if (!$owner || !hash_equals((string)$owner['username'], $user) || !password_verify($hash, (string)$owner['password_hash'])) {
        respond(['error' => 'Invalid credentials'], 401);
    }
    respond(['user' => $owner['username'], 'token' => issue_token($pdo, (int)$owner['id'])]);
}

if ($action === 'change-password' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = require_user($pdo);
    $input = input_json();
    $currentHash = (string)($input['currentHash'] ?? '');
    $newHash = (string)($input['newHash'] ?? '');
    $query = $pdo->prepare('SELECT password_hash FROM mm_users WHERE id = ?');
    $query->execute([$user['id']]);
    $current = $query->fetchColumn();
    if (!$current || !password_verify($currentHash, (string)$current)) respond(['error' => 'Invalid current password'], 401);
    if (!preg_match('/^[a-f0-9]{8,128}$/', $newHash)) respond(['error' => 'Invalid new password'], 400);
    $pdo->prepare('UPDATE mm_users SET password_hash = ? WHERE id = ?')->execute([password_hash($newHash, PASSWORD_DEFAULT), $user['id']]);
    $pdo->prepare('DELETE FROM mm_sessions WHERE user_id = ?')->execute([$user['id']]);
    respond(['token' => issue_token($pdo, (int)$user['id'])]);
}

respond(['error' => 'Not found'], 404);
