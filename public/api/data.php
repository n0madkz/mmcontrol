<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$pdo = database();
$user = require_user($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $query = $pdo->prepare('SELECT data, updated_at FROM mm_app_state WHERE user_id = ?');
    $query->execute([$user['id']]);
    $row = $query->fetch();
    respond(['data' => $row ? json_decode($row['data'], true) : null, 'updatedAt' => $row['updated_at'] ?? null]);
}

if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $data = input_json();
    if (!isset($data['objects'], $data['payments'], $data['expenses'], $data['companies']) || !is_array($data['objects']) || !is_array($data['payments']) || !is_array($data['expenses']) || !is_array($data['companies'])) {
        respond(['error' => 'Invalid database format'], 400);
    }
    $payload = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($payload === false) respond(['error' => 'Unable to encode data'], 400);
    $query = $pdo->prepare('INSERT INTO mm_app_state (user_id, data) VALUES (?, ?) ON DUPLICATE KEY UPDATE data = VALUES(data), updated_at = CURRENT_TIMESTAMP');
    $query->execute([$user['id'], $payload]);
    respond(['ok' => true]);
}

respond(['error' => 'Method not allowed'], 405);
