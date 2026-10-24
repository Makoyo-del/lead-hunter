<?php
declare(strict_types=1);

/**
 * Hardened Prospect Engagement Tracker & Lead Webhook
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
// 2. HARDENED LOGGING & LIVE LEAD SUBMISSION ENDPOINT
// ─────────────────────────────────────────────────────────────

// Parse parameters from JSON body, POST, or GET
$inputData = [];
$rawBody = file_get_contents('php://input');
if ($rawBody !== false && strlen($rawBody) > 0) {
    $json = json_decode($rawBody, true);
    if (is_array($json)) {
        $inputData = $json;
    }
}

$rawStore = (string)($inputData['store'] ?? $_POST['store'] ?? $_GET['store'] ?? '');
$rawEvent = (string)($inputData['event'] ?? $_POST['event'] ?? $_GET['event'] ?? '');

// Strict Input Validation on store
if (!preg_match('/^[a-z0-9\-]{2,60}$/', $rawStore)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid store parameter: Must be 2-60 lowercase alphanumeric/hyphen characters'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$allowedEvents = ['page_view', 'csv_download', 'xlsx_download', 'lead_submission'];
if (!in_array($rawEvent, $allowedEvents, true)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid event parameter: Must be page_view, csv_download, xlsx_download, or lead_submission'
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

// Handle lead submission payload
if ($rawEvent === 'lead_submission') {
    $rawName = (string)($inputData['name'] ?? $_POST['name'] ?? '');
    $rawEmail = (string)($inputData['email'] ?? $_POST['email'] ?? '');
    $rawChoice = (string)($inputData['choice'] ?? $_POST['choice'] ?? 'free_test_5');
    $rawNote = (string)($inputData['note'] ?? $_POST['note'] ?? '');

    $cleanName = preg_replace('/[^a-zA-Z0-9\s\.\-]/', '', substr($rawName, 0, 100)) ?: 'Anonymous Merchant';
    $cleanEmail = filter_var(trim($rawEmail), FILTER_VALIDATE_EMAIL);

    if (!$cleanEmail) {
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'message' => 'Please provide a valid business email address.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $cleanChoice = in_array($rawChoice, ['free_test_5', 'full_upgrade'], true) ? $rawChoice : 'free_test_5';
    $cleanNote = htmlspecialchars(substr($rawNote, 0, 1000), ENT_QUOTES, 'UTF-8');

    $record['name'] = $cleanName;
    $record['email'] = $cleanEmail;
    $record['choice'] = $cleanChoice;
    $record['note'] = $cleanNote;

    // Immediately dispatch notification to Duncan via Resend API
    $resendApiKey = (string)getenv('RESEND_API_KEY');
    if (empty($resendApiKey)) {
        $candidateFiles = [$parentDir . '/.resend_key', $parentDir . '/.env', __DIR__ . '/.resend_key'];
        foreach ($candidateFiles as $cfg) {
            if (is_file($cfg) && is_readable($cfg)) {
                $content = (string)file_get_contents($cfg);
                if (str_contains($content, 'RESEND_API_KEY=')) {
                    foreach (explode("\n", $content) as $line) {
                        $line = trim($line);
                        if (str_starts_with($line, 'RESEND_API_KEY=')) {
                            $resendApiKey = trim(substr($line, 15));
                            break 2;
                        }
                    }
                } elseif (str_starts_with(trim($content), 're_')) {
                    $resendApiKey = trim($content);
                    break;
                }
            }
        }
    }
    if (!empty($resendApiKey)) {
        $choiceLabel = ($cleanChoice === 'full_upgrade') ? 'Full Catalog Upgrade ($395-$550)' : 'Push 5 Free Samples to Drafts';
        $emailHtml = "<div style='font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#FAF7F2;border-radius:12px;border:1px solid #E5E7EB;'>"
            . "<h2 style='color:#0B2418;margin-top:0;'>🚨 New Inbound Lead Submission!</h2>"
            . "<p>A store owner just submitted the instant approval modal on their audit page:</p>"
            . "<table style='width:100%;border-collapse:collapse;margin:16px 0;'>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;border-bottom:1px solid #E5E7EB;'>Store:</td><td style='padding:8px;border-bottom:1px solid #E5E7EB;'><strong>{$rawStore}</strong></td></tr>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;border-bottom:1px solid #E5E7EB;'>Name:</td><td style='padding:8px;border-bottom:1px solid #E5E7EB;'>{$cleanName}</td></tr>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;border-bottom:1px solid #E5E7EB;'>Email:</td><td style='padding:8px;border-bottom:1px solid #E5E7EB;'><a href='mailto:{$cleanEmail}'>{$cleanEmail}</a></td></tr>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;border-bottom:1px solid #E5E7EB;'>Selection:</td><td style='padding:8px;border-bottom:1px solid #E5E7EB;'><span style='background:#B9FF66;color:#0B2418;padding:4px 8px;border-radius:6px;font-weight:bold;'>{$choiceLabel}</span></td></tr>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;border-bottom:1px solid #E5E7EB;'>Note / Time:</td><td style='padding:8px;border-bottom:1px solid #E5E7EB;'>" . ($cleanNote ?: 'None provided') . "</td></tr>"
            . "<tr><td style='padding:8px;font-weight:bold;color:#4B5563;'>Timestamp:</td><td style='padding:8px;'>" . date('Y-m-d H:i:s T') . "</td></tr>"
            . "</table>"
            . "<div style='margin-top:20px;'><a href='mailto:{$cleanEmail}?subject=Re:%20Shopify%20Catalog%20Upgrade%20for%20{$rawStore}&body=Hey%20{$cleanName},' style='background:#0B2418;color:#FFFFFF;padding:12px 24px;text-decoration:none;border-radius:8px;font-weight:bold;display:inline-block;'>Reply to {$cleanName} Directly</a></div>"
            . "</div>";

        $resendPayload = json_encode([
            'from' => 'Shopify Audit Lead <duncan@duncanmakoyo.com>',
            'to' => ['duncan@duncanmakoyo.com'],
            'subject' => "🚨 NEW INBOUND LEAD: {$cleanName} ({$rawStore}) - {$choiceLabel}",
            'html' => $emailHtml
        ]);

        if (function_exists('curl_init')) {
            $ch = curl_init('https://api.resend.com/emails');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $resendPayload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $resendApiKey,
                'Content-Type: application/json'
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 4);
            @curl_exec($ch);
            @curl_close($ch);
        }
    }
}

// Append record to log file safely
$line = json_encode($record, JSON_UNESCAPED_SLASHES) . "\n";
@file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);

http_response_code(200);
echo json_encode([
    'status' => 'ok',
    'store' => $rawStore,
    'event' => $rawEvent,
    'message' => ($rawEvent === 'lead_submission') ? 'Submission received successfully' : 'Event logged'
], JSON_UNESCAPED_SLASHES);
