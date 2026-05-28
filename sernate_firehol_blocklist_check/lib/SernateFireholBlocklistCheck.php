<?php

declare(strict_types=1);

final class SernateFireholBlocklistCheck
{
    public const VERSION = '0.1.2';
    public const PLUGIN_ID = 'sernate_firehol_blocklist_check';
    public const DEFAULT_API_BASE_URL = 'https://blocklist.sernate.com';
    public const TEST_IP = '223.244.22.213';
    public const UPDATE_URL = 'https://blocklist.sernate.com/sernate_firehol_blocklist_check.tar.gz';
    public const VERSION_URL = 'https://blocklist.sernate.com/version.txt';
    public const CONFIG_FILE = __DIR__ . '/../data/config.json';
    public const STATE_FILE = __DIR__ . '/../state/last_result.json';
    public const DEBUG_FILE = __DIR__ . '/../state/debug.json';
    public const LOCK_FILE = __DIR__ . '/../state/check.lock';

    public static function defaultConfig(): array
    {
        return [
            'api_base_url' => self::DEFAULT_API_BASE_URL,
            'schedule_enabled' => false,
            'schedule_interval_hours' => 6,
            'notify_on_new_listings' => true,
            'notification_method' => 'directadmin',
            'notification_email' => '',
            'notification_from' => '',
            'investigation_mode' => false,
            'last_scheduled_run_at' => null,
        ];
    }

    public static function loadDirectAdminRequest(): void
    {
        $_GET = self::parseDirectAdminRequestString((string) getenv('QUERY_STRING'));
        $_POST = self::parseDirectAdminRequestString((string) getenv('POST'));
    }

    public static function parseDirectAdminRequestString(string $value): array
    {
        if ($value === '') {
            return [];
        }

        $parsed = [];
        parse_str(html_entity_decode($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $parsed);

        $clean = [];
        foreach ($parsed as $key => $item) {
            if (is_string($key)) {
                $clean[urldecode($key)] = is_string($item) ? urldecode($item) : $item;
            }
        }

        return $clean;
    }

    public static function loadConfig(): array
    {
        $config = self::defaultConfig();
        if (is_file(self::CONFIG_FILE)) {
            $raw = file_get_contents(self::CONFIG_FILE);
            $decoded = json_decode($raw ?: '', true);
            if (is_array($decoded)) {
                $config = array_merge($config, $decoded);
            }
        }

        $config['schedule_interval_hours'] = self::normalizeInterval((int) $config['schedule_interval_hours']);
        $config['api_base_url'] = self::DEFAULT_API_BASE_URL;
        $config['investigation_mode'] = (bool) $config['investigation_mode'];
        $config['current_only'] = !$config['investigation_mode'];
        $config['include_stale'] = $config['investigation_mode'];
        if (!in_array($config['notification_method'], ['directadmin', 'email', 'both'], true)) {
            $config['notification_method'] = 'directadmin';
        }

        if ($config['investigation_mode']) {
            $config['current_only'] = false;
            $config['include_stale'] = true;
        }

        return $config;
    }

    public static function saveConfig(array $input): void
    {
        $config = self::loadConfig();
        $config['api_base_url'] = self::DEFAULT_API_BASE_URL;
        $config['schedule_enabled'] = !empty($input['schedule_enabled']);
        $config['schedule_interval_hours'] = self::normalizeInterval((int) ($input['schedule_interval_hours'] ?? 6));
        $config['notify_on_new_listings'] = !empty($input['notify_on_new_listings']);
        $config['notification_method'] = in_array(($input['notification_method'] ?? ''), ['directadmin', 'email', 'both'], true)
            ? (string) $input['notification_method']
            : 'directadmin';
        $config['notification_email'] = filter_var((string) ($input['notification_email'] ?? ''), FILTER_VALIDATE_EMAIL)
            ? (string) $input['notification_email']
            : '';
        $config['notification_from'] = filter_var((string) ($input['notification_from'] ?? ''), FILTER_VALIDATE_EMAIL)
            ? (string) $input['notification_from']
            : '';
        $config['investigation_mode'] = !empty($input['investigation_mode']);
        $config['current_only'] = !$config['investigation_mode'];
        $config['include_stale'] = $config['investigation_mode'];

        self::ensureWritableDirs();
        self::writeJson(self::CONFIG_FILE, $config);
    }

    public static function normalizeInterval(int $hours): int
    {
        return in_array($hours, [4, 6, 8, 12, 24], true) ? $hours : 6;
    }

    public static function ensureWritableDirs(): void
    {
        foreach ([dirname(self::CONFIG_FILE), dirname(self::STATE_FILE)] as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }
        }
    }

    public static function publicIpv4Addresses(): array
    {
        return self::ipDetectionDebug()['ips'];
    }

    public static function ipDetectionDebug(): array
    {
        $ips = [];
        $debug = [];
        $commands = [
            '/sbin/ip -4 -o addr show scope global 2>/dev/null',
            '/usr/sbin/ip -4 -o addr show scope global 2>/dev/null',
            'ip -4 -o addr show scope global 2>/dev/null',
            'hostname -I 2>/dev/null',
        ];

        foreach ($commands as $command) {
            $output = shell_exec($command);
            if (!is_string($output) || trim($output) === '') {
                continue;
            }

            $found = [];
            if (strpos($command, ' addr show ') !== false) {
                preg_match_all('/\binet\s+((?:\d{1,3}\.){3}\d{1,3})\/\d+\b/', $output, $matches);
                $found = $matches[1] ?? [];
            } else {
                preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $output, $matches);
                $found = $matches[0] ?? [];
            }

            foreach ($found as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $ips[$candidate] = true;
                }
            }

            $debug[] = [
                'command' => preg_replace('/\s+/', ' ', $command),
                'found' => array_values(array_unique($found)),
                'output' => substr(trim($output), 0, 1200),
            ];
        }

        $ips = array_keys($ips);
        sort($ips);

        return [
            'ips' => $ips,
            'commands' => $debug,
        ];
    }

    public static function runCheck(?array $ips = null, ?array $config = null): array
    {
        $config = $config ?? self::loadConfig();
        $ips = $ips ?? self::publicIpv4Addresses();
        sort($ips);

        if ($ips === []) {
            return self::recordResult([
                'ok' => false,
                'status' => 'no_public_ips',
                'message' => 'No public IPv4 addresses were detected on this server.',
                'checked_at' => gmdate('c'),
                'ips' => [],
                'api' => null,
                'debug' => self::runtimeDebug($config, $ips, null),
            ]);
        }

        $query = http_build_query([
            'current_only' => $config['current_only'] ? 'true' : 'false',
            'include_stale' => $config['include_stale'] ? 'true' : 'false',
        ]);
        $url = rtrim((string) $config['api_base_url'], '/') . '/search?' . $query;
        $body = implode(',', $ips);

        $response = self::httpPost($url, $body);
        if (!$response['ok']) {
            return self::recordResult([
                'ok' => false,
                'status' => 'api_unavailable',
                'message' => $response['error'] ?: 'The Sernate Blocklist API is unavailable.',
                'checked_at' => gmdate('c'),
                'ips' => $ips,
                'api' => $response,
                'debug' => self::runtimeDebug($config, $ips, $response),
            ]);
        }

        $json = json_decode((string) $response['body'], true);
        if (!is_array($json)) {
            return self::recordResult([
                'ok' => false,
                'status' => 'api_unavailable',
                'message' => 'The API returned an invalid response.',
                'checked_at' => gmdate('c'),
                'ips' => $ips,
                'api' => $response,
                'debug' => self::runtimeDebug($config, $ips, $response),
            ]);
        }

        $status = self::classifyStatus($json, $config);
        $result = [
            'ok' => true,
            'status' => $status,
            'message' => self::resultMessage($status, count($ips)),
            'checked_at' => gmdate('c'),
            'ips' => $ips,
            'api' => $json,
            'debug' => self::runtimeDebug($config, $ips, ['ok' => true, 'status_code' => 200, 'error' => '']),
        ];

        return self::recordResult($result);
    }

    public static function loadLastResult(): ?array
    {
        if (!is_file(self::STATE_FILE)) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents(self::STATE_FILE), true);
        return is_array($decoded) ? $decoded : null;
    }

    public static function recordDebug(string $action, array $extra = []): void
    {
        self::ensureWritableDirs();
        self::writeJson(self::DEBUG_FILE, array_merge([
            'action' => $action,
            'at' => gmdate('c'),
            'request_method' => (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
            'content_length' => (string) ($_SERVER['CONTENT_LENGTH'] ?? ''),
            'env_query_string' => (string) getenv('QUERY_STRING'),
            'env_post' => substr((string) getenv('POST'), 0, 1200),
            'post_keys' => array_keys($_POST),
            'get_keys' => array_keys($_GET),
        ], $extra));
    }

    public static function loadDebug(): ?array
    {
        if (!is_file(self::DEBUG_FILE)) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents(self::DEBUG_FILE), true);
        return is_array($decoded) ? $decoded : null;
    }

    public static function dueForScheduledRun(array $config): bool
    {
        if (empty($config['schedule_enabled'])) {
            return false;
        }

        $last = self::loadLastResult();
        if (!$last || empty($last['checked_at'])) {
            return true;
        }

        $lastTs = strtotime((string) $last['checked_at']);
        if (!$lastTs) {
            return true;
        }

        return time() - $lastTs >= ((int) $config['schedule_interval_hours'] * 3600);
    }

    public static function scheduledCheck(): array
    {
        $config = self::loadConfig();
        if (!self::dueForScheduledRun($config)) {
            return ['ran' => false, 'message' => 'Not due.'];
        }

        self::ensureWritableDirs();
        $lock = fopen(self::LOCK_FILE, 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['ran' => false, 'message' => 'Another check is already running.'];
        }

        $previous = self::loadLastResult();
        $result = self::runCheck(null, $config);

        if (!empty($config['notify_on_new_listings']) && self::hasNewActiveListing($previous, $result)) {
            self::notify($result, $config);
        }

        flock($lock, LOCK_UN);
        fclose($lock);

        return ['ran' => true, 'result' => $result];
    }

    public static function hasNewActiveListing(?array $previous, array $current): bool
    {
        if (($current['status'] ?? '') !== 'listed') {
            return false;
        }

        $before = self::activeListedIps($previous);
        $after = self::activeListedIps($current);
        return array_values(array_diff($after, $before)) !== [];
    }

    public static function activeListedIps(?array $result): array
    {
        if (!$result || empty($result['api']['results']) || !is_array($result['api']['results'])) {
            return [];
        }

        $ips = [];
        foreach ($result['api']['results'] as $row) {
            if (!empty($row['currently_blacklisted']) && !empty($row['ip'])) {
                $ips[] = (string) $row['ip'];
            }
        }

        sort($ips);
        return array_values(array_unique($ips));
    }

    public static function notify(array $result, array $config): void
    {
        $method = (string) ($config['notification_method'] ?? 'directadmin');

        if ($method === 'directadmin' || $method === 'both') {
            self::notifyAdmin($result);
        }

        if (($method === 'email' || $method === 'both') && !empty($config['notification_email'])) {
            self::notifyEmail($result, (string) $config['notification_email'], (string) ($config['notification_from'] ?? ''));
        }
    }

    public static function notifyAdmin(array $result): void
    {
        $ips = implode(', ', self::activeListedIps($result));
        $subject = rawurlencode('Sernate FireHOL Blocklist Check: IP listed');
        $message = rawurlencode("One or more public server IPs appear in indexed FireHOL blocklists.\n\nIPs: " . $ips . "\n\nOpen DirectAdmin > Sernate FireHOL Blocklist Check for details.");
        $line = "action=notify&value=admin&subject={$subject}&message={$message}\n";
        // This plugin reports listings only; it never changes firewall rules.
        @file_put_contents('/usr/local/directadmin/data/task.queue', $line, FILE_APPEND | LOCK_EX);
    }

    public static function notifyEmail(array $result, string $to, string $from = ''): void
    {
        if (!function_exists('mail') || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
            return;
        }

        $ips = implode(', ', self::activeListedIps($result));
        $subject = 'Sernate FireHOL Blocklist Check: IP listed';
        $message = "One or more public server IPs appear in indexed FireHOL blocklists.\n\nIPs: {$ips}\n\nOpen DirectAdmin > Sernate FireHOL Blocklist Check for details.";
        $headers = [];
        if ($from !== '' && filter_var($from, FILTER_VALIDATE_EMAIL)) {
            $headers[] = 'From: ' . $from;
            $headers[] = 'Reply-To: ' . $from;
        }

        @mail($to, $subject, $message, implode("\r\n", $headers));
    }

    public static function resultRows(?array $result): array
    {
        if (!$result) {
            return [];
        }

        $rows = [];
        foreach (($result['api']['results'] ?? []) as $row) {
            if (!empty($row['ip'])) {
                $rows[(string) $row['ip']] = $row;
            }
        }

        foreach (($result['ips'] ?? []) as $ip) {
            $ip = (string) $ip;
            if (!isset($rows[$ip])) {
                $rows[$ip] = [
                    'ip' => $ip,
                    'currently_blacklisted' => false,
                    'hits' => [],
                    'hits_count' => 0,
                ];
            }
        }

        ksort($rows);
        return array_values($rows);
    }

    public static function hitStatusLabel(array $hit): string
    {
        if (($hit['current_status'] ?? '') === 'present') {
            return 'currently listed';
        }

        if (($hit['current_status'] ?? '') === 'absent') {
            return 'historical only';
        }

        return (string) ($hit['current_status'] ?? 'unknown');
    }

    public static function updateStatus(): array
    {
        $response = self::httpGet(self::VERSION_URL);
        if (!$response['ok']) {
            return [
                'ok' => false,
                'installed' => self::VERSION,
                'latest' => null,
                'update_available' => false,
                'message' => $response['error'] ?: 'Could not check for updates.',
            ];
        }

        $latest = self::extractVersion((string) $response['body']);
        if ($latest === null) {
            return [
                'ok' => false,
                'installed' => self::VERSION,
                'latest' => null,
                'update_available' => false,
                'message' => 'Update version file did not contain a version number.',
            ];
        }

        $available = version_compare($latest, self::VERSION, '>');

        return [
            'ok' => true,
            'installed' => self::VERSION,
            'latest' => $latest,
            'update_available' => $available,
            'message' => $available ? 'A new plugin version is available.' : 'Plugin is up to date.',
            'update_url' => self::UPDATE_URL,
            'version_url' => self::VERSION_URL,
        ];
    }

    public static function extractVersion(string $body): ?string
    {
        if (preg_match('/\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/', $body, $match)) {
            return $match[1];
        }

        return null;
    }

    public static function classifyStatus(array $api, array $config): string
    {
        if ((int) ($api['currently_blacklisted_count'] ?? 0) > 0) {
            return 'listed';
        }

        if (!$config['current_only'] && (int) ($api['blacklisted_count'] ?? 0) > 0) {
            return 'history_only';
        }

        foreach (($api['results'] ?? []) as $result) {
            foreach (($result['hits'] ?? []) as $hit) {
                if (!empty($hit['source_is_stale'])) {
                    return 'stale_source';
                }
            }
        }

        return 'clean';
    }

    public static function statusLabel(string $status): string
    {
        return [
            'not_checked' => 'Not Checked Yet',
            'clean' => 'Clean',
            'listed' => 'Listed',
            'history_only' => 'History Only',
            'stale_source' => 'Stale Source',
            'api_unavailable' => 'API Unavailable',
            'no_public_ips' => 'No Public IPv4 Detected',
        ][$status] ?? ucfirst(str_replace('_', ' ', $status));
    }

    public static function resultMessage(string $status, int $checkedCount): string
    {
        if ($status === 'clean') {
            return 'Clean: none of the ' . $checkedCount . ' checked IP address(es) were found in current fresh FireHOL blocklists.';
        }

        if ($status === 'listed') {
            return 'Listed: one or more checked IP address(es) appear in indexed FireHOL blocklists.';
        }

        return self::statusLabel($status);
    }

    public static function httpPost(string $url, string $body): array
    {
        if (!function_exists('curl_init')) {
            return ['ok' => false, 'error' => 'PHP cURL extension is not available.', 'status_code' => 0, 'body' => null];
        }

        $ch = curl_init($url);
        if (!$ch) {
            return ['ok' => false, 'error' => 'Unable to initialize cURL.', 'status_code' => 0, 'body' => null];
        }

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => [
                'Content-Type: text/plain',
                'Accept: application/json',
                'User-Agent: Sernate-FireHOL-Blocklist-Check-DirectAdmin/' . self::VERSION,
            ],
        ]);

        $responseBody = curl_exec($ch);
        $error = curl_error($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [
            'ok' => $responseBody !== false && $statusCode >= 200 && $statusCode < 300,
            'error' => $error ?: ($statusCode >= 400 ? 'HTTP ' . $statusCode : ''),
            'status_code' => $statusCode,
            'body' => $responseBody,
        ];
    }

    public static function httpGet(string $url): array
    {
        if (!function_exists('curl_init')) {
            return ['ok' => false, 'error' => 'PHP cURL extension is not available.', 'status_code' => 0, 'body' => null];
        }

        $ch = curl_init($url);
        if (!$ch) {
            return ['ok' => false, 'error' => 'Unable to initialize cURL.', 'status_code' => 0, 'body' => null];
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_HTTPHEADER => [
                'Accept: text/plain',
                'User-Agent: Sernate-FireHOL-Blocklist-Check-DirectAdmin/' . self::VERSION,
            ],
        ]);

        $responseBody = curl_exec($ch);
        $error = curl_error($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [
            'ok' => $responseBody !== false && $statusCode >= 200 && $statusCode < 300,
            'error' => $error ?: ($statusCode >= 400 ? 'HTTP ' . $statusCode : ''),
            'status_code' => $statusCode,
            'body' => $responseBody,
        ];
    }

    public static function html(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function writeJson(string $path, array $value): void
    {
        file_put_contents($path, json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    }

    private static function recordResult(array $result): array
    {
        self::ensureWritableDirs();
        self::writeJson(self::STATE_FILE, $result);
        self::recordDebug('run_check', [
            'result_status' => $result['status'] ?? null,
            'result_message' => $result['message'] ?? null,
            'result_ips' => $result['ips'] ?? [],
            'runtime' => $result['debug'] ?? null,
        ]);

        return $result;
    }

    private static function runtimeDebug(array $config, array $ips, ?array $response): array
    {
        return [
            'api_base_url' => $config['api_base_url'] ?? self::DEFAULT_API_BASE_URL,
            'current_only' => !empty($config['current_only']),
            'include_stale' => !empty($config['include_stale']),
            'detected_ips' => $ips,
            'http_status' => $response['status_code'] ?? null,
            'http_error' => $response['error'] ?? null,
            'ip_detection' => self::ipDetectionDebug(),
        ];
    }
}
