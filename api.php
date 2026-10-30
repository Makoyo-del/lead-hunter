<?php
declare(strict_types=1);

/**
 * Shopify Catalog Intelligence — Stateless Live Diagnostic & MCP Discovery Engine (api.php)
 * Author: Duncan Makoyo (duncan@duncanmakoyo.com)
 *
 * Features:
 * - Zero database, 100% stateless execution.
 * - Strict SSRF protection & domain validation.
 * - Live public storefront audit (/products.json) checking taxonomy, descriptions, alt text & variants.
 * - Real-time JSON-RPC 2.0 calls to https://mcp.shop.com/ (tools/call -> search_catalog, protocol 2026-07-28).
 * - Honest, defensible classification: OBSERVED, NOT_OBSERVED_IN_SAMPLE, DATA_ISSUE_FOUND.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

const MCP_ENDPOINT = 'https://mcp.shop.com/';
const MCP_PROTOCOL_VERSION = '2026-07-28';

// Parse input from JSON POST or GET query parameters
$input = [];
$rawBody = file_get_contents('php://input');
if ($rawBody !== false && strlen($rawBody) > 0) {
    $decoded = json_decode($rawBody, true);
    if (is_array($decoded)) {
        $input = $decoded;
    }
}

enforceRateLimit();

$mode = (string)($input['mode'] ?? $_GET['mode'] ?? 'domain'); // 'domain' or 'search'
$rawDomain = trim((string)($input['domain'] ?? $_GET['domain'] ?? ''));
$rawQuery = trim((string)($input['query'] ?? $_GET['query'] ?? ''));
$country = strtoupper(substr(trim((string)($input['country'] ?? $_GET['country'] ?? 'US')), 0, 2));
if (!in_array($country, ['US', 'CA', 'GB', 'AU'], true)) {
    $country = 'US';
}
$currencyMap = ['US' => 'USD', 'CA' => 'CAD', 'GB' => 'GBP', 'AU' => 'AUD'];
$currency = $currencyMap[$country] ?? 'USD';

/**
 * Strict SSRF & Domain Validation
 */
function sanitizeAndValidateDomain(string $raw): ?string {
    $clean = strtolower(trim($raw));
    $clean = preg_replace('#^https?://#i', '', $clean);
    $clean = explode('/', $clean)[0];
    $clean = explode('?', $clean)[0];
    $clean = explode(':', $clean)[0];
    $clean = preg_replace('/^www\./i', '', $clean);

    if (empty($clean) || strlen($clean) > 120) {
        return null;
    }
    // Must be a valid hostname with a public TLD
    if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/', $clean)) {
        return null;
    }
    $blocked = ['localhost', '127.0.0.1', '0.0.0.0', 'internal', 'local', 'example.com'];
    foreach ($blocked as $b) {
        if ($clean === $b || str_ends_with($clean, '.' . $b)) {
            return null;
        }
    }
    // Resolve IP to prevent private network SSRF
    $ip = @gethostbyname($clean);
    if ($ip && $ip !== $clean) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return null;
        }
    }
    return $clean;
}

/**
 * ── MCP access layer: cache + parallel prefetch ──────────────────────────────
 * Public catalog search results (NOT merchant data) are cached for 15 minutes in the
 * system temp dir. This keeps repeated/demo queries instant and keeps load off mcp.shop.com
 * so many visitors can use the scanner at the same time.
 */
const MCP_CACHE_TTL = 900;
$GLOBALS['MCP_MEMO'] = [];

function mcpCacheKey(string $q, int $limit, string $country, string $currency): string {
    return sha1(strtolower(trim($q)) . "|{$limit}|{$country}|{$currency}");
}

function mcpCacheDir(): string {
    $d = rtrim(sys_get_temp_dir(), '/\\') . '/catalog_scanner_cache';
    if (!is_dir($d)) {
        @mkdir($d, 0700, true);
    }
    return $d;
}

function mcpCacheGet(string $key): ?array {
    $f = mcpCacheDir() . "/{$key}.json";
    if (is_file($f) && (time() - (int)@filemtime($f)) < MCP_CACHE_TTL) {
        $d = json_decode((string)@file_get_contents($f), true);
        if (is_array($d)) {
            return $d;
        }
    }
    return null;
}

function mcpCachePut(string $key, array $products): void {
    if (empty($products)) {
        return; // never cache failures / empty results
    }
    $f = mcpCacheDir() . "/{$key}.json";
    $tmp = $f . '.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, json_encode($products, JSON_UNESCAPED_SLASHES)) !== false) {
        @rename($tmp, $f);
    }
    // Opportunistic cleanup (1% of writes)
    if (random_int(1, 100) === 1) {
        foreach ((array)@glob(mcpCacheDir() . '/*.json') as $old) {
            if (time() - (int)@filemtime($old) > MCP_CACHE_TTL * 4) {
                @unlink($old);
            }
        }
    }
}

function buildMcpCurl(string $query, int $limit, string $country, string $currency) {
    $payload = [
        'jsonrpc' => '2.0',
        'id' => random_int(10000, 999999),
        'method' => 'tools/call',
        'params' => [
            'name' => 'search_catalog',
            'arguments' => [
                'catalog' => [
                    'query' => $query,
                    'context' => ['address_country' => $country, 'currency' => $currency],
                    'pagination' => ['limit' => $limit]
                ]
            ],
            '_meta' => [
                'io.modelcontextprotocol/protocolVersion' => MCP_PROTOCOL_VERSION,
                'io.modelcontextprotocol/clientInfo' => [
                    'name' => 'shopify-catalog-intelligence-scanner',
                    'version' => '2.0.0'
                ],
                'io.modelcontextprotocol/clientCapabilities' => new stdClass()
            ]
        ]
    ];

    $ch = curl_init(MCP_ENDPOINT);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Accept: application/json, text/event-stream',
            'MCP-Protocol-Version: ' . MCP_PROTOCOL_VERSION,
            'Mcp-Method: tools/call',
            'Mcp-Name: search_catalog',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ],
        CURLOPT_TIMEOUT => 12,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => false
    ]);
    return $ch;
}

function parseMcpRaw($resp, int $httpCode): array {
    if ($resp === false || $resp === null || $httpCode !== 200) {
        return [];
    }
    $data = json_decode((string)$resp, true);
    $content = $data['result']['content'] ?? [];
    if (!is_array($content) || empty($content[0]['text'])) {
        return [];
    }
    $parsed = json_decode((string)$content[0]['text'], true);
    $raw = $parsed['products'] ?? [];
    return is_array($raw) ? $raw : [];
}

/** Single raw fetch: memo -> disk cache -> network */
function fetchMcpRaw(string $query, int $limit, string $country, string $currency): array {
    $key = mcpCacheKey($query, $limit, $country, $currency);
    if (isset($GLOBALS['MCP_MEMO'][$key])) {
        return $GLOBALS['MCP_MEMO'][$key];
    }
    $cached = mcpCacheGet($key);
    if ($cached !== null) {
        return $GLOBALS['MCP_MEMO'][$key] = $cached;
    }
    $ch = buildMcpCurl($query, $limit, $country, $currency);
    $resp = @curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    @curl_close($ch);
    $raw = parseMcpRaw($resp, $code);
    mcpCachePut($key, $raw);
    return $GLOBALS['MCP_MEMO'][$key] = $raw;
}

/**
 * Runs all uncached MCP searches IN PARALLEL (curl_multi) so one scan takes ~1 round-trip
 * instead of 5 sequential ones. $jobs = [[query, limit], ...]
 */
function mcpPrefetch(array $jobs, string $country, string $currency): void {
    $pending = [];
    foreach ($jobs as [$q, $limit]) {
        $key = mcpCacheKey($q, $limit, $country, $currency);
        if (isset($GLOBALS['MCP_MEMO'][$key])) {
            continue;
        }
        $cached = mcpCacheGet($key);
        if ($cached !== null) {
            $GLOBALS['MCP_MEMO'][$key] = $cached;
            continue;
        }
        $pending[$key] = [$q, $limit];
    }
    if (empty($pending) || !function_exists('curl_multi_init')) {
        return;
    }

    $mh = curl_multi_init();
    $handles = [];
    foreach ($pending as $key => [$q, $limit]) {
        $ch = buildMcpCurl($q, $limit, $country, $currency);
        curl_multi_add_handle($mh, $ch);
        $handles[$key] = $ch;
    }
    $running = null;
    do {
        $status = curl_multi_exec($mh, $running);
        if ($running > 0) {
            curl_multi_select($mh, 1.0);
        }
    } while ($running > 0 && $status === CURLM_OK);

    foreach ($handles as $key => $ch) {
        $resp = curl_multi_getcontent($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $raw = parseMcpRaw($resp, $code);
        mcpCachePut($key, $raw);
        $GLOBALS['MCP_MEMO'][$key] = $raw;
        curl_multi_remove_handle($mh, $ch);
        @curl_close($ch);
    }
    curl_multi_close($mh);
}

/**
 * Calls Shopify MCP search_catalog (cached / prefetched) and normalizes results
 */
function callShopMcpSearch(string $query, int $limit = 8, string $country = 'US', string $currency = 'USD', string $targetDomain = ''): array {
    return normalizeMcpProducts(fetchMcpRaw($query, $limit, $country, $currency), $targetDomain);
}

/**
 * Per-IP rate limit (file based, stateless re: merchant data). Protects the shared MCP endpoint
 * and Hostinger PHP workers from abuse while allowing many concurrent legit users.
 */
function enforceRateLimit(int $max = 30, int $windowSec = 60): void {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $file = mcpCacheDir() . '/rl_' . sha1((string)$ip) . '.txt';
    $now = time();
    $fh = @fopen($file, 'c+');
    if (!$fh) {
        return;
    }
    @flock($fh, LOCK_EX);
    $raw = trim((string)stream_get_contents($fh));
    $times = $raw === '' ? [] : array_filter(array_map('intval', explode(',', $raw)), fn($t) => $t > $now - $windowSec);
    if (count($times) >= $max) {
        @flock($fh, LOCK_UN);
        @fclose($fh);
        http_response_code(429);
        header('Retry-After: ' . $windowSec);
        echo json_encode(['status' => 'error', 'message' => 'Too many scans from your network in the last minute. Please wait a few seconds and try again.']);
        exit;
    }
    $times[] = $now;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode(',', $times));
    @flock($fh, LOCK_UN);
    @fclose($fh);
}

/**
 * Normalizes MCP product objects into clean frontend-friendly cards
 */
function normalizeMcpProducts(array $rawProducts, string $targetDomain = ''): array {
    $normalized = [];
    $cleanTarget = strtolower($targetDomain);

    foreach ($rawProducts as $idx => $prod) {
        $variant = $prod['variants'][0] ?? [];
        $seller = $variant['seller'] ?? [];
        $sellerName = (string)($seller['name'] ?? 'Shopify Merchant');
        $sellerUrl = (string)($seller['url'] ?? '');
        $sellerDomainRaw = (string)($seller['domain'] ?? '');

        $cleanSellerUrl = strtolower((string)preg_replace('#^https?://(www\.)?#i', '', $sellerUrl));
        $cleanSellerUrl = explode('/', $cleanSellerUrl)[0];
        $cleanSellerDom = strtolower((string)preg_replace('#^https?://(www\.)?#i', '', $sellerDomainRaw));

        $isTargetMatch = false;
        if ($cleanTarget !== '') {
            if (
                ($cleanSellerUrl !== '' && (str_contains($cleanSellerUrl, $cleanTarget) || str_contains($cleanTarget, $cleanSellerUrl))) ||
                ($cleanSellerDom !== '' && (str_contains($cleanSellerDom, $cleanTarget) || str_contains($cleanTarget, $cleanSellerDom)))
            ) {
                $isTargetMatch = true;
            }
        }

        $priceAmount = $variant['price']['amount'] ?? $prod['price_range']['min']['amount'] ?? 0;
        $priceCurrency = (string)($variant['price']['currency'] ?? $prod['price_range']['min']['currency'] ?? 'USD');
        $priceFormatted = $priceAmount > 0 ? sprintf('$%.2f %s', $priceAmount / 100, $priceCurrency) : 'Price Varies';

        $imageUrl = (string)($prod['media'][0]['preview']['url'] ?? $prod['media'][0]['url'] ?? $variant['media'][0]['url'] ?? '');
        $altText = (string)($prod['media'][0]['alt_text'] ?? '');

        $metadata = $prod['metadata'] ?? [];
        $techSpecs = is_array($metadata['tech_specs'] ?? null) ? array_slice($metadata['tech_specs'], 0, 5) : [];
        $topFeatures = is_array($metadata['top_features'] ?? null) ? array_slice($metadata['top_features'], 0, 4) : [];
        $usp = (string)($metadata['unique_selling_points'][0] ?? '');

        $ratingVal = $prod['rating']['value'] ?? $variant['rating']['value'] ?? null;
        $ratingCount = $prod['rating']['count'] ?? $variant['rating']['count'] ?? 0;

        $normalized[] = [
            'rank' => $idx + 1,
            'id' => (string)($prod['id'] ?? ''),
            'title' => (string)($prod['title'] ?? 'Untitled Product'),
            'handle' => (string)($prod['handle'] ?? ''),
            'price' => $priceFormatted,
            'price_cents' => (int)$priceAmount,
            'image_url' => $imageUrl,
            'alt_text' => $altText,
            'seller_name' => $sellerName,
            'seller_domain' => $cleanSellerUrl ?: $cleanSellerDom,
            'seller_url' => $sellerUrl,
            'product_url' => (string)($variant['url'] ?? $sellerUrl),
            'checkout_url' => (string)($variant['checkout_url'] ?? ''),
            'has_shop_pay' => !empty($variant['checkout_url']),
            'is_target_merchant' => $isTargetMatch,
            'rating' => $ratingVal ? round((float)$ratingVal, 1) : null,
            'rating_count' => (int)$ratingCount,
            'usp' => $usp,
            'tech_specs' => $techSpecs,
            'top_features' => $topFeatures,
            'has_ai_metadata' => (!empty($techSpecs) || !empty($topFeatures) || !empty($usp))
        ];
    }

    return $normalized;
}

/**
 * Fetches public /products.json from a Shopify storefront
 */
function fetchStorefrontProducts(string $domain, int $limit = 5): array {
    $urls = [
        "https://{$domain}/products.json?limit={$limit}",
        "https://www.{$domain}/products.json?limit={$limit}"
    ];

    foreach ($urls as $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json,text/plain,*/*',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            ],
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3
        ]);
        $resp = @curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        @curl_close($ch);

        if ($resp !== false && $code === 200) {
            $json = json_decode((string)$resp, true);
            if (is_array($json) && isset($json['products']) && is_array($json['products'])) {
                return $json['products'];
            }
        }
    }
    return [];
}

/**
 * Generates a generic category / intent search query from a product title & type
 */
function buildCategoryIntentQuery(string $title, string $productType, string $vendor): string {
    $cleanTitle = preg_replace('/[^a-zA-Z0-9\s\-]/', ' ', $title);
    if ($vendor !== '') {
        $cleanTitle = str_ireplace($vendor, '', $cleanTitle);
    }
    $words = array_values(array_filter(explode(' ', trim($cleanTitle)), fn($w) => strlen($w) > 2));
    $coreWords = implode(' ', array_slice($words, 0, 5));
    if ($productType !== '' && !str_contains(strtolower($coreWords), strtolower($productType))) {
        return trim($coreWords . ' ' . $productType);
    }
    return $coreWords ?: $title;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE 1: DIRECT 1-BILLION PRODUCT CATALOG SEARCH
// ─────────────────────────────────────────────────────────────────────────────
if ($mode === 'search') {
    if ($rawQuery === '') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Please enter a product or category search query.']);
        exit;
    }
    $cleanDomain = $rawDomain !== '' ? (sanitizeAndValidateDomain($rawDomain) ?? '') : '';
    $results = callShopMcpSearch($rawQuery, 15, $country, $currency, $cleanDomain);

    echo json_encode([
        'status' => 'ok',
        'mode' => 'search',
        'query' => $rawQuery,
        'target_domain' => $cleanDomain,
        'country' => $country,
        'timestamp' => date('c'),
        'total_returned' => count($results),
        'catalog_products' => $results
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// MODE 2: FULL STOREFRONT + MCP DISCOVERY DIAGNOSTIC
// ─────────────────────────────────────────────────────────────────────────────
$domain = sanitizeAndValidateDomain($rawDomain);
if ($domain === null) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Please enter a valid public Shopify store domain (e.g., monodsports.com or thehandmadehouse.ca).'
    ]);
    exit;
}

$storeProducts = fetchStorefrontProducts($domain, 5);
$knownBrands = [
    'monodsports.com' => 'Monod Sports',
    'thehandmadehouse.ca' => 'The Handmade House',
    'theblock.ca' => 'The Block',
    'belleetrebelle.ca' => 'Belle et Rebelle',
    'cafeterra.ca' => 'Terra Coffee & Tea',
    'sojournoutdoors.com' => 'Sojourn Outdoors',
    'trailshop.com' => 'The Trail Shop',
    'simoneandivy.ca' => 'Simone & Ivy',
    'blueruby.com' => 'Blue Ruby Jewellery',
    'leapfrogoutdoor.com' => 'Leapfrog Outdoor',
    'shopmagnoliaandsalt.com' => 'Magnolia & Salt',
    'thesouthernoutfitter.com' => 'The Southern Outfitter',
    'shopgraycesboutique.com' => 'Grayces Boutique'
];
$domainRoot = explode('.', $domain)[0];
$brandGuess = $knownBrands[$domain] ?? ucwords(str_replace(['-', '_'], ' ', $domainRoot));

if (empty($storeProducts)) {
    // Storefront /products.json is restricted or not standard; run brand-level MCP discovery check
    $brandResults = callShopMcpSearch($brandGuess, 12, $country, $currency, $domain);
    $observedCount = count(array_filter($brandResults, fn($p) => $p['is_target_merchant']));

    echo json_encode([
        'status' => 'ok',
        'mode' => 'domain',
        'domain' => $domain,
        'brand_name' => $brandGuess,
        'public_feed_accessible' => false,
        'timestamp' => date('c'),
        'summary' => [
            'sampled_products_count' => 0,
            'queries_tested' => 1,
            'exact_observed_count' => $observedCount > 0 ? 1 : 0,
            'intent_observed_count' => 0,
            'data_issues_count' => 0,
            'readiness_score' => $observedCount > 0 ? 55 : 28,
            'status_classification' => $observedCount > 0 ? 'OBSERVED' : 'NOT_OBSERVED_IN_SAMPLE'
        ],
        'product_observations' => [],
        'catalog_grid' => $brandResults,
        'raw_sample_json' => null
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// Analyze up to 3 flagship products across Both Engine A (Storefront Data Quality) & Engine B (Shop MCP Discovery)
$sampledSlice = array_slice($storeProducts, 0, 3);
if (!isset($knownBrands[$domain]) && !empty($sampledSlice[0]['vendor'])) {
    $vCandidate = (string)$sampledSlice[0]['vendor'];
    $vClean = strtolower((string)preg_replace('/[^a-z0-9]/i', '', $vCandidate));
    if ($vClean !== '' && (str_contains($domainRoot, $vClean) || str_contains($vClean, $domainRoot))) {
        $brandGuess = $vCandidate;
    }
}

// Fire every MCP query for this scan in parallel (exact + intent), then the loop below reads from memory
$prefetchJobs = [];
foreach ($sampledSlice as $pIdx => $pSp) {
    $pTitle = (string)($pSp['title'] ?? 'Untitled Product');
    $pType = trim((string)($pSp['product_type'] ?? ''));
    $pVendor = trim((string)($pSp['vendor'] ?? $brandGuess));
    $prefetchJobs[] = [trim("{$pTitle} {$brandGuess}"), 6];
    if ($pIdx < 2) {
        $prefetchJobs[] = [buildCategoryIntentQuery($pTitle, $pType, $pVendor), 6];
    }
}
mcpPrefetch($prefetchJobs, $country, $currency);

$productObservations = [];
$catalogGridMap = [];
$exactObservedTotal = 0;
$intentObservedTotal = 0;
$dataIssuesTotal = 0;
$queriesTested = 0;

foreach ($sampledSlice as $idx => $sp) {
    $title = (string)($sp['title'] ?? 'Untitled Product');
    $handle = (string)($sp['handle'] ?? '');
    $productType = trim((string)($sp['product_type'] ?? ''));
    $vendor = trim((string)($sp['vendor'] ?? $brandGuess));
    $bodyHtml = (string)($sp['body_html'] ?? '');
    $plainDesc = trim(strip_tags($bodyHtml));
    $wordCount = $plainDesc === '' ? 0 : str_word_count($plainDesc);

    $tagsRaw = $sp['tags'] ?? [];
    $tags = is_array($tagsRaw) ? $tagsRaw : array_filter(array_map('trim', explode(',', (string)$tagsRaw)));

    $firstImage = $sp['images'][0]['src'] ?? '';
    $firstAlt = trim((string)($sp['images'][0]['alt'] ?? ''));
    $firstVariant = $sp['variants'][0] ?? [];
    $priceStr = isset($firstVariant['price']) ? '$' . number_format((float)$firstVariant['price'], 2) : 'N/A';

    // Engine A: Storefront Data Integrity Checks
    $defects = [];
    if ($wordCount < 45) {
        $defects[] = $wordCount === 0
            ? 'Empty product description in feed (0 words)'
            : "Thin product description ({$wordCount} words — lacks structured specs)";
    }
    if ($productType === '') {
        $defects[] = 'Unmapped product_type / missing Shopify Standard Taxonomy category';
    }
    if ($firstAlt === '') {
        $defects[] = 'Missing image alt-text accessibility metadata';
    }
    if (count($tags) < 2) {
        $defects[] = 'Sparse attribute tags (' . count($tags) . ' tags)';
    }
    if (count($sp['variants'] ?? []) === 1 && ($firstVariant['title'] ?? '') === 'Default Title') {
        $defects[] = 'Single Default Title variant (no structured material/size/color option schema)';
    }

    if (!empty($defects)) {
        $dataIssuesTotal++;
    }

    // Engine B: Global Catalog MCP Discovery Queries
    // Query 1: Exact Product + Brand Search
    $exactQuery = trim("{$title} {$brandGuess}");
    $exactResults = callShopMcpSearch($exactQuery, 6, $country, $currency, $domain);
    $queriesTested++;

    $exactMatchedItem = null;
    $exactCompetitors = [];
    foreach ($exactResults as $rItem) {
        $catalogGridMap[$rItem['id'] ?: $rItem['title']] = $rItem;
        if ($rItem['is_target_merchant'] && $exactMatchedItem === null) {
            $exactMatchedItem = $rItem;
        } elseif (!$rItem['is_target_merchant']) {
            $exactCompetitors[] = $rItem;
        }
    }
    if ($exactMatchedItem !== null) {
        $exactObservedTotal++;
    }

    // Query 2: Generic Category / Buyer Intent Search (Run for first 2 products to keep response snappy < 4s)
    $intentQuery = buildCategoryIntentQuery($title, $productType, $vendor);
    $intentMatchedItem = null;
    $intentCompetitors = [];
    if ($idx < 2) {
        $intentResults = callShopMcpSearch($intentQuery, 6, $country, $currency, $domain);
        $queriesTested++;
        foreach ($intentResults as $rItem) {
            $catalogGridMap[$rItem['id'] ?: $rItem['title']] = $rItem;
            if ($rItem['is_target_merchant'] && $intentMatchedItem === null) {
                $intentMatchedItem = $rItem;
            } elseif (!$rItem['is_target_merchant']) {
                $intentCompetitors[] = $rItem;
            }
        }
        if ($intentMatchedItem !== null) {
            $intentObservedTotal++;
        }
    }

    // Honest Classification
    $classification = 'OBSERVED';
    if ($exactMatchedItem === null) {
        $classification = 'NOT_OBSERVED_IN_SAMPLE';
    } elseif (!empty($defects)) {
        $classification = 'DATA_ISSUE_FOUND';
    }

    $productObservations[] = [
        'title' => $title,
        'handle' => $handle,
        'product_url' => "https://{$domain}/products/{$handle}",
        'image_url' => $firstImage,
        'price' => $priceStr,
        'word_count' => $wordCount,
        'product_type' => $productType ?: null,
        'alt_text' => $firstAlt ?: null,
        'tags_count' => count($tags),
        'defects' => $defects,
        'classification' => $classification,
        'exact_search' => [
            'query' => $exactQuery,
            'status' => $exactMatchedItem !== null ? 'OBSERVED' : 'NOT_OBSERVED_IN_SAMPLE',
            'rank' => $exactMatchedItem['rank'] ?? null,
            'matched_offer' => $exactMatchedItem,
            'competing_offers' => array_slice($exactCompetitors, 0, 3)
        ],
        'intent_search' => $idx < 2 ? [
            'query' => $intentQuery,
            'status' => $intentMatchedItem !== null ? 'OBSERVED' : 'NOT_OBSERVED_IN_SAMPLE',
            'rank' => $intentMatchedItem['rank'] ?? null,
            'matched_offer' => $intentMatchedItem,
            'competing_offers' => array_slice($intentCompetitors, 0, 3)
        ] : null
    ];
}

// Compute transparent Readiness Score
$totalSampled = count($sampledSlice);
$discoveryRatio = $totalSampled > 0 ? ($exactObservedTotal / $totalSampled) : 0;
$intentRatio = $totalSampled > 0 ? ($intentObservedTotal / min(2, $totalSampled)) : 0;
$defectPenalty = $totalSampled > 0 ? (($dataIssuesTotal / $totalSampled) * 35) : 25;

$readinessScore = (int)round(max(14, min(96, ($discoveryRatio * 45) + ($intentRatio * 30) + (25 - ($defectPenalty * 0.6)))));

// Build raw sample JSON for the MCP Payload Inspector
$firstRaw = $sampledSlice[0] ?? [];
$rawInspectorSample = [
    'storefront_feed_json' => [
        'id' => $firstRaw['id'] ?? null,
        'title' => $firstRaw['title'] ?? '',
        'handle' => $firstRaw['handle'] ?? '',
        'product_type' => $firstRaw['product_type'] ?: null,
        'body_html_word_count' => isset($firstRaw['body_html']) ? str_word_count(trim(strip_tags((string)$firstRaw['body_html']))) : 0,
        'image_alt_text' => $firstRaw['images'][0]['alt'] ?? null,
        'tags' => is_array($firstRaw['tags'] ?? null) ? array_slice($firstRaw['tags'], 0, 5) : []
    ],
    'recommended_mcp_enriched_schema' => [
        'title' => $firstRaw['title'] ?? '',
        'shopify_standard_taxonomy' => $firstRaw['product_type'] ?: 'Apparel & Accessories > Specialized Category (Requires Mapping)',
        'metadata' => [
            'unique_selling_points' => [
                "Structured high-intent value proposition tailored for {$brandGuess} shoppers and AI discovery."
            ],
            'top_features' => [
                'Verified material composition & construction attribute mapping',
                'Explicit use-case & buyer intent compatibility tags',
                'Complete variant option labels for autonomous filtering'
            ],
            'tech_specs' => [
                'Brand: ' . $brandGuess,
                'Category: ' . ($firstRaw['product_type'] ?: 'Unmapped (Fix Required)'),
                'Image Alt-Text: Descriptive accessibility string mapped',
                'Channel Feed Sync: Shop Catalog & Agentic Storefront Ready'
            ]
        ]
    ]
];

echo json_encode([
    'status' => 'ok',
    'mode' => 'domain',
    'domain' => $domain,
    'brand_name' => $brandGuess,
    'country' => $country,
    'public_feed_accessible' => true,
    'timestamp' => date('c'),
    'summary' => [
        'sampled_products_count' => $totalSampled,
        'queries_tested' => $queriesTested,
        'exact_observed_count' => $exactObservedTotal,
        'intent_observed_count' => $intentObservedTotal,
        'data_issues_count' => $dataIssuesTotal,
        'readiness_score' => $readinessScore
    ],
    'product_observations' => $productObservations,
    'catalog_grid' => array_values(array_slice($catalogGridMap, 0, 15)),
    'raw_sample_json' => $rawInspectorSample
], JSON_UNESCAPED_SLASHES);
