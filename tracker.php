<?php
declare(strict_types=1);

/**
 * Hardened Prospect Engagement Tracker & Read Endpoint
 * PHP 8.2 / 8.3+ Compliant
 * Hostinger Git Deployment Safe (.audits_events_log.jsonl stored above Git root)
 * Author: Duncan Makoyo (duncan@duncanmakoyo.com)
 */

// Timing-safe secret token for CRM read authorization
const TRACKER_TOKEN = 'trk_9f8b2a14e6d3c7b801a2f4e5d6c7b8a9';

// Security Headers
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Determine safe storage path (1 directory above Git root to survive Git pull/deploy)
$parentDir = dirname(__DIR__);
$primaryLog = $parentDir . '/.audits_events_log.jsonl';
$fallbackLog = __DIR__ . '/.events_log.jsonl';

$logFile = is_writable($parentDir) ? $primaryLog : $fallbackLog;

$action = isset($_GET['action']) ? (string)$_GET['action'] : 'log';

// ─────────────────────────────────────────────────────────────
// 1. AUTHENTICATED READ ENDPOINT (FOR 7_track_crm.py)
// ─────────────────────────────────────────────────────────────
if ($action === 'read') {
    $tokenProvided = isset($_GET['token']) ? (string)$_GET['token'] : '';
    $expectedToken = (string)(getenv('TRACKER_SECRET_TOKEN') ?: TRACKER_TOKEN);

    if (!hash_equals($expectedToken, $tokenProvided)) {
        http_response_code(403);
        echo json_encode([
            'status' => 'error',
            'message' => 'Unauthorized: Invalid or missing authentication token'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $events = [];
    $candidateFiles = array_unique([$primaryLog, $fallbackLog]);

    foreach ($candidateFiles as $file) {
        if (is_file($file) && is_readable($file)) {
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $decoded = json_decode($line, true);
                    if (is_array($decoded)) {
                        $events[] = $decoded;
                    }
                }
            }
        }
    }

    http_response_code(200);
    echo json_encode([
        'status' => 'ok',
        'count' => count($events),
        'events' => $events
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─────────────────────────────────────────────────────────────
// 2. HARDENED LOGGING ENDPOINT (FOR PAGE VIEWS & CSV DOWNLOADS)
// ─────────────────────────────────────────────────────────────
$rawStore = isset($_GET['store']) ? (string)$_GET['store'] : '';
$rawEvent = isset($_GET['event']) ? (string)$_GET['event'] : '';

// Strict Input Validation
if (!preg_match('/^[a-z0-9\-]{2,60}$/', $rawStore)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid store parameter: Must be 2-60 lowercase alphanumeric/hyphen characters'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$allowedEvents = ['page_view', 'csv_download'];
if (!in_array($rawEvent, $allowedEvents, true)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid event parameter: Must be page_view or csv_download'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// Sanitize Client Metadata
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $ip = (string)$_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
    $ip = trim($parts[0]);
}

$ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string)$_SERVER['HTTP_USER_AGENT'], 0, 300) : '';
$referer = isset($_SERVER['HTTP_REFERER']) ? substr((string)$_SERVER['HTTP_REFERER'], 0, 300) : '';

$record = [
    'timestamp' => date('c'),
    'store' => $rawStore,
    'event' => $rawEvent,
    'ip' => filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0',
    'user_agent' => $ua,
    'referrer' => $referer
];

$line = json_encode($record, JSON_UNESCAPED_SLASHES) . "\n";
@file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);

http_response_code(200);
echo json_encode([
    'status' => 'logged',
    'store' => $rawStore,
    'event' => $rawEvent
], JSON_UNESCAPED_SLASHES);
