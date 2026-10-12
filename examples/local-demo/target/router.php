<?php

declare(strict_types=1);

/**
 * Deterministic local target resource (development demo only).
 *
 * Routes:
 *   GET  /hello?name=X   -> 200 JSON greeting
 *   POST /echo           -> 200 JSON echo of method, content type, body
 *   GET  /not-found      -> 404 JSON
 *   GET  /error          -> 500 JSON
 *   anything else        -> 404 JSON
 */

require __DIR__ . '/../lib/HttpKernel.php';

header('Content-Type: application/json');

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$body = file_get_contents('php://input') ?: '';

switch (true) {
    case $method === 'GET' && $path === '/hello':
        $name = $_GET['name'] ?? 'world';
        http_response_code(200);
        echo json_encode([
            'message' => 'Hello, ' . $name . '!',
            'served_by' => 'ohttphp-local-target',
        ], JSON_UNESCAPED_SLASHES);
        break;

    case $method === 'POST' && $path === '/echo':
        http_response_code(200);
        echo json_encode([
            'method' => $method,
            'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
            'body_length' => strlen($body),
            'body' => $body,
        ], JSON_UNESCAPED_SLASHES);
        break;

    case $method === 'GET' && $path === '/not-found':
        http_response_code(404);
        echo json_encode(['title' => 'Not found', 'status' => 404], JSON_UNESCAPED_SLASHES);
        break;

    case $method === 'GET' && $path === '/error':
        http_response_code(500);
        echo json_encode(['title' => 'Target internal error', 'status' => 500], JSON_UNESCAPED_SLASHES);
        break;

    default:
        http_response_code(404);
        echo json_encode(['title' => 'Not found', 'status' => 404], JSON_UNESCAPED_SLASHES);
        break;
}