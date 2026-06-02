<?php

declare(strict_types=1);

final class SernateFireholBlocklistCheck
{
    public const VERSION = '0.1.23';
    public const PLUGIN_ID = 'sernate_firehol_blocklist_check';
    public const DEFAULT_API_BASE_URL = 'https://blocklist.sernate.com';
    public const UPDATE_URL = 'https://github.com/WeszNL/directadmin-firehol-ip-blocklist-check/releases/latest/download/sernate_firehol_blocklist_check.tar.gz';
    public const VERSION_URL = 'https://github.com/WeszNL/directadmin-firehol-ip-blocklist-check/releases/latest/download/version.txt';
    public const UPDATE_CACHE_TTL = 43200;

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

    public static function storageDir(): string
    {
        $localStateDir = __DIR__ . '/../state';
        $runtime = self::runtimeUser();
        if ((string) ($runtime['user'] ?? '') === 'diradmin' || (string) getenv('RUNNING_AS') === 'diradmin') {
            return $localStateDir;
        }

        $user = self::directAdminUsername();
        $daUserDir = '/usr/local/directadmin/data/users/' . $user;
        if ($user !== '' && is_dir($daUserDir)) {
            return $daUserDir . '/plugins/' . self::PLUGIN_ID;
        }

        return $localStateDir;
    }

    public static function configFile(): string
    {
        return self::storageDir() . '/config.json';
    }

    public static function debugServerIpsFile(): string
    {
        return self::storageDir() . '/debug_server_ips.txt';
    }

    public static function stateFile(): string
    {
        return self::storageDir() . '/last_result.json';
    }

    public static function ipCacheFile(): string
    {
        return self::storageDir() . '/ip_cache.json';
    }

    public static function updateCacheFile(): string
    {
        return self::storageDir() . '/update_cache.json';
    }

    public static function debugFile(): string
    {
        return self::storageDir() . '/debug.json';
    }

    public static function installMarkerFile(): string
    {
        return self::storageDir() . '/install_marker.txt';
    }

    public static function lockFile(): string
    {
        return self::storageDir() . '/check.lock';
    }

    public static function directAdminUsername(): string
    {
        $user = (string) getenv('USERNAME');
        if ($user !== '') {
            return preg_replace('/[^A-Za-z0-9_.-]/', '', $user) ?? '';
        }

        $runtime = self::runtimeUser();
        $runtimeUser = preg_replace('/[^A-Za-z0-9_.-]/', '', (string) ($runtime['user'] ?? '')) ?? '';
        if ($runtimeUser !== '' && is_dir('/usr/local/directadmin/data/users/' . $runtimeUser)) {
            return $runtimeUser;
        }

        if (is_readable('/usr/local/directadmin/data/admin/admin.list')) {
            $admins = file('/usr/local/directadmin/data/admin/admin.list', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($admins) && !empty($admins[0])) {
                return preg_replace('/[^A-Za-z0-9_.-]/', '', (string) $admins[0]) ?? '';
            }
        }

        return $runtimeUser;
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
        if (is_file(self::configFile())) {
            $raw = file_get_contents(self::configFile());
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
        self::writeJson(self::configFile(), $config);
    }

    public static function normalizeInterval(int $hours): int
    {
        return in_array($hours, [4, 6, 8, 12, 24], true) ? $hours : 6;
    }

    public static function validManualIpv4(string $ip): ?string
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip;
        }

        return null;
    }

    public static function ensureWritableDirs(): void
    {
        foreach ([dirname(self::configFile()), dirname(self::stateFile())] as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }
        }
    }

    public static function publicIpv4Addresses(): array
    {
        $ips = [];
        foreach (array_merge(self::ipDetectionDebug()['ips'], self::debugServerIps()) as $ip) {
            $ips[$ip] = true;
        }

        $ips = array_keys($ips);
        sort($ips);

        return $ips;
    }

    public static function debugServerIps(): array
    {
        if (!is_file(self::debugServerIpsFile())) {
            return [];
        }

        $raw = (string) file_get_contents(self::debugServerIpsFile());
        preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $raw, $matches);

        $ips = [];
        foreach (($matches[0] ?? []) as $candidate) {
            if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                $ips[$candidate] = true;
            }
        }

        $ips = array_keys($ips);
        sort($ips);

        return $ips;
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

    public static function runCheck(?array $ips = null, ?array $config = null, string $scope = 'server'): array
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
                'scope' => $scope,
                'ips' => [],
                'api' => null,
                'debug' => self::runtimeDebug($config, $ips, null),
            ], $scope);
        }

        $response = count($ips) === 1
            ? self::searchSingleIp((string) $config['api_base_url'], $ips[0], $config)
            : self::searchMultipleIps((string) $config['api_base_url'], $ips, $config);

        if (!$response['ok']) {
            $status = self::statusFromHttpResponse($response);
            return self::recordResult([
                'ok' => false,
                'status' => $status,
                'message' => self::apiErrorMessage($response),
                'checked_at' => gmdate('c'),
                'scope' => $scope,
                'ips' => $ips,
                'api' => self::safeHttpResponse($response),
                'debug' => self::runtimeDebug($config, $ips, $response),
            ], $scope);
        }

        $json = json_decode((string) $response['body'], true);
        if (!is_array($json)) {
            return self::recordResult([
                'ok' => false,
                'status' => 'api_unavailable',
                'message' => 'The API returned an invalid response.',
                'checked_at' => gmdate('c'),
                'scope' => $scope,
                'ips' => $ips,
                'api' => self::safeHttpResponse($response),
                'debug' => self::runtimeDebug($config, $ips, $response),
            ], $scope);
        }

        $status = self::classifyStatus($json, $config);
        $result = [
            'ok' => true,
            'status' => $status,
            'message' => self::resultMessage($status, count($ips)),
            'checked_at' => gmdate('c'),
            'scope' => $scope,
            'ips' => $ips,
            'api' => $json,
            'debug' => self::runtimeDebug($config, $ips, ['ok' => true, 'status_code' => 200, 'error' => '']),
        ];

        return self::recordResult($result, $scope);
    }

    public static function searchSingleIp(string $apiBaseUrl, string $ip, array $config): array
    {
        $query = http_build_query([
            'v' => $ip,
            'current_only' => !empty($config['current_only']) ? 'true' : 'false',
            'include_stale' => !empty($config['include_stale']) ? 'true' : 'false',
        ]);

        return self::httpGet(rtrim($apiBaseUrl, '/') . '/search/ip?' . $query, 'application/json');
    }

    public static function searchMultipleIps(string $apiBaseUrl, array $ips, array $config): array
    {
        $query = http_build_query([
            'current_only' => !empty($config['current_only']) ? 'true' : 'false',
            'include_stale' => !empty($config['include_stale']) ? 'true' : 'false',
        ]);
        $url = rtrim($apiBaseUrl, '/') . '/search?' . $query;
        $body = implode(',', $ips);

        return self::httpPost($url, $body);
    }

    public static function loadLastResult(): ?array
    {
        if (!is_file(self::stateFile())) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents(self::stateFile()), true);
        return is_array($decoded) ? $decoded : null;
    }

    public static function loadIpCache(): array
    {
        if (!is_file(self::ipCacheFile())) {
            return [];
        }

        $decoded = json_decode((string) file_get_contents(self::ipCacheFile()), true);
        return is_array($decoded) ? $decoded : [];
    }

    public static function recordDebug(string $action, array $extra = []): void
    {
        self::ensureWritableDirs();
        self::writeJson(self::debugFile(), array_merge([
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
        if (!is_file(self::debugFile())) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents(self::debugFile()), true);
        return is_array($decoded) ? $decoded : null;
    }

    public static function installHealth(): array
    {
        $cronFile = '/etc/cron.d/sernate-firehol-blocklist-check';
        $scriptFile = __DIR__ . '/../scripts/check.php';

        return [
            'cron_ok' => is_file($cronFile),
            'cron_file' => $cronFile,
            'check_script_ok' => is_file($scriptFile),
            'check_script' => realpath($scriptFile) ?: $scriptFile,
            'php_version' => PHP_VERSION,
            'php_ok' => PHP_VERSION_ID >= 70100,
            'curl_ok' => function_exists('curl_init'),
            'runtime_user' => self::runtimeUser(),
            'plugin_dir' => realpath(__DIR__ . '/..') ?: (__DIR__ . '/..'),
            'data_dir' => dirname(self::configFile()),
            'data_dir_writable' => is_dir(dirname(self::configFile())) && is_writable(dirname(self::configFile())),
            'state_dir' => dirname(self::stateFile()),
            'state_dir_writable' => is_dir(dirname(self::stateFile())) && is_writable(dirname(self::stateFile())),
            'storage_dir' => self::storageDir(),
            'storage_user' => self::directAdminUsername(),
            'last_result_file_exists' => is_file(self::stateFile()),
            'debug_file_exists' => is_file(self::debugFile()),
            'install_marker' => is_file(self::installMarkerFile()) ? trim((string) file_get_contents(self::installMarkerFile())) : '',
            'debug_server_ips' => self::debugServerIps(),
            'debug_server_ips_file' => self::debugServerIpsFile(),
            'update_cache' => self::updateCacheDebug(),
            'last_debug' => self::loadDebug(),
        ];
    }

    public static function runtimeUser(): array
    {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
        $gid = function_exists('posix_getegid') ? posix_getegid() : getmygid();
        $userInfo = function_exists('posix_getpwuid') ? posix_getpwuid((int) $uid) : false;
        $groupInfo = function_exists('posix_getgrgid') ? posix_getgrgid((int) $gid) : false;

        return [
            'uid' => $uid,
            'gid' => $gid,
            'user' => is_array($userInfo) ? (string) ($userInfo['name'] ?? '') : '',
            'group' => is_array($groupInfo) ? (string) ($groupInfo['name'] ?? '') : '',
            'file_owner_user' => get_current_user(),
        ];
    }

    public static function updateCacheDebug(): array
    {
        $path = self::updateCacheFile();
        $dir = dirname($path);
        $debug = [
            'file' => $path,
            'exists' => is_file($path),
            'dir_writable' => is_dir($dir) && is_writable($dir),
            'checked_at' => null,
            'age_seconds' => null,
            'ttl_seconds' => self::UPDATE_CACHE_TTL,
            'latest' => null,
            'ok' => null,
        ];

        if (!is_file($path)) {
            return $debug;
        }

        $decoded = json_decode((string) file_get_contents($path), true);
        if (!is_array($decoded)) {
            return $debug;
        }

        $checkedAt = strtotime((string) ($decoded['checked_at'] ?? ''));
        $debug['checked_at'] = (string) ($decoded['checked_at'] ?? '');
        $debug['age_seconds'] = $checkedAt ? time() - $checkedAt : null;
        $debug['latest'] = (string) ($decoded['status']['latest'] ?? '');
        $debug['ok'] = isset($decoded['status']['ok']) ? (bool) $decoded['status']['ok'] : null;

        return $debug;
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

    public static function scheduledCheck(bool $force = false): array
    {
        $config = self::loadConfig();
        if (!$force && !self::dueForScheduledRun($config)) {
            return ['ran' => false, 'message' => 'Not due.'];
        }

        self::ensureWritableDirs();
        $lock = fopen(self::lockFile(), 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return ['ran' => false, 'message' => 'Another check is already running.'];
        }

        $previous = self::loadLastResult();
        $result = self::runCheck(null, $config);

        $shouldNotify = !empty($config['notify_on_new_listings']) && ($force || self::hasNewActiveListing($previous, $result));
        if ($shouldNotify) {
            self::notify($result, $config);
        }

        flock($lock, LOCK_UN);
        fclose($lock);

        return ['ran' => true, 'forced' => $force, 'notified' => $shouldNotify, 'result' => $result];
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
        $subject = rawurlencode(self::notificationSubject());
        $message = rawurlencode(
            "One or more IPs on this server were found on a FireHOL-based blocklist.\n\n"
            . "Server: " . self::serverName() . "\n"
            . "IP(s): " . $ips . "\n\n"
            . "Open the plugin for details:\n"
            . "/CMD_PLUGINS_ADMIN/" . self::PLUGIN_ID
        );
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
        $subject = self::notificationSubject();
        $message = "One or more IPs on this server were found on a FireHOL-based blocklist.\n\n"
            . "Server: " . self::serverName() . "\n"
            . "IP(s): {$ips}\n\n"
            . "Open DirectAdmin > Sernate FireHOL Blocklist Check for details.";
        $headers = [
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'X-Mailer: Sernate FireHOL Blocklist Check DirectAdmin Plugin/' . self::VERSION,
            'Auto-Submitted: auto-generated',
        ];
        $mailArgs = '';
        if ($from !== '' && filter_var($from, FILTER_VALIDATE_EMAIL)) {
            $from = self::cleanHeaderValue($from);
            $headers[] = 'From: ' . self::mailboxHeader(self::mailFromName(), $from);
            $headers[] = 'Reply-To: ' . self::mailboxHeader(self::mailFromName(), $from);
            $mailArgs = '-f ' . escapeshellarg($from);
        }

        @mail($to, $subject, $message, implode("\r\n", $headers), $mailArgs);
    }

    public static function notificationSubject(): string
    {
        return 'DirectAdmin ' . self::serverName() . ': server IP found on blocklist';
    }

    public static function serverName(): string
    {
        $name = gethostname();
        if (is_string($name) && trim($name) !== '') {
            return self::cleanHeaderValue($name);
        }

        return 'server';
    }

    public static function mailFromName(): string
    {
        return 'DirectAdmin Blocklist Check (' . self::serverName() . ')';
    }

    public static function mailboxHeader(string $name, string $email): string
    {
        $name = trim(str_replace(['"', "\r", "\n"], '', $name));
        $email = self::cleanHeaderValue($email);

        return '"' . addcslashes($name, '\\') . '" <' . $email . '>';
    }

    public static function resultRows(?array $result): array
    {
        if (!$result) {
            return [];
        }

        $cache = self::loadIpCache();
        $checkedAt = (string) ($result['checked_at'] ?? '');
        $rows = [];
        foreach (($result['api']['results'] ?? []) as $row) {
            if (!empty($row['ip'])) {
                $row['last_checked_at'] = $checkedAt !== '' ? $checkedAt : (string) ($cache[(string) $row['ip']]['checked_at'] ?? '');
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
                    'last_checked_at' => $checkedAt !== '' ? $checkedAt : (string) ($cache[$ip]['checked_at'] ?? ''),
                ];
            } elseif (empty($rows[$ip]['last_checked_at'])) {
                $rows[$ip]['last_checked_at'] = $checkedAt !== '' ? $checkedAt : (string) ($cache[$ip]['checked_at'] ?? '');
            }
        }

        ksort($rows);
        return array_values($rows);
    }

    public static function activeHits(array $row): array
    {
        $hits = [];
        foreach (($row['hits'] ?? []) as $hit) {
            if (!is_array($hit)) {
                continue;
            }

            if (($hit['current_status'] ?? '') === 'present') {
                $hits[] = $hit;
            }
        }

        return $hits;
    }

    public static function historyHits(array $row): array
    {
        $hits = [];
        foreach (($row['hits'] ?? []) as $hit) {
            if (!is_array($hit)) {
                continue;
            }

            if (($hit['current_status'] ?? '') === 'absent') {
                $hits[] = $hit;
            }
        }

        return $hits;
    }

    public static function rowStatusLabel(array $row): string
    {
        if (!empty($row['currently_blacklisted'])) {
            return 'Listed';
        }

        if (self::historyHits($row) !== []) {
            return 'History only';
        }

        return 'Clear';
    }

    public static function rowStatusClass(array $row): string
    {
        if (!empty($row['currently_blacklisted'])) {
            return 'listed';
        }

        if (self::historyHits($row) !== []) {
            return 'history';
        }

        return 'clean';
    }

    public static function rowFeedSummary(array $row): string
    {
        $active = count(self::activeHits($row));
        $history = count(self::historyHits($row));

        if ($active > 0) {
            $summary = $active . ' current feed' . ($active === 1 ? '' : 's');
            if ($history > 0) {
                $summary .= ', ' . $history . ' historical';
            }

            return $summary;
        }

        if ($history > 0) {
            return $history . ' historical feed' . ($history === 1 ? '' : 's');
        }

        return 'No current listing in checked FireHOL feeds.';
    }

    public static function hitDateSummary(array $hit): string
    {
        $added = self::humanTime((string) ($hit['last_added'] ?? $hit['first_seen'] ?? ''));
        $removed = self::humanTime((string) ($hit['last_removed'] ?? ''));
        $parts = [];

        if ($added !== 'Never') {
            $parts[] = 'Added ' . $added;
        }

        if ($removed !== 'Never') {
            $parts[] = 'Removed ' . $removed;
        }

        return implode(' / ', $parts);
    }

    public static function hitEvidence(array $hit): string
    {
        $matchedEntry = trim((string) ($hit['matched_entry'] ?? ''));
        if ($matchedEntry === '') {
            return '';
        }

        $matchedIp = trim((string) ($hit['matched_ip'] ?? ''));
        if ($matchedIp === '') {
            return 'CIDR match - matched feed entry ' . $matchedEntry;
        }

        return 'CIDR match - ' . $matchedIp . ' falls within ' . $matchedEntry;
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
        $cached = self::loadUpdateCache();
        if ($cached !== null) {
            return $cached;
        }

        $response = self::httpGet(self::VERSION_URL);
        if (!$response['ok']) {
            return self::saveUpdateCache([
                'ok' => false,
                'installed' => self::VERSION,
                'latest' => null,
                'update_available' => false,
                'message' => $response['error'] ?: 'Could not check for updates.',
            ]);
        }

        $latest = self::extractVersion((string) $response['body']);
        if ($latest === null) {
            return self::saveUpdateCache([
                'ok' => false,
                'installed' => self::VERSION,
                'latest' => null,
                'update_available' => false,
                'message' => 'Update version file did not contain a version number.',
            ]);
        }

        $available = version_compare($latest, self::VERSION, '>');

        return self::saveUpdateCache([
            'ok' => true,
            'installed' => self::VERSION,
            'latest' => $latest,
            'update_available' => $available,
            'message' => $available ? 'A new plugin version is available.' : 'Plugin is up to date.',
            'update_url' => self::UPDATE_URL,
            'version_url' => self::VERSION_URL,
        ]);
    }

    public static function updateStatusFromCache(): array
    {
        $cached = self::loadUpdateCache();
        if ($cached !== null) {
            return $cached;
        }

        return [
            'ok' => true,
            'installed' => self::VERSION,
            'latest' => 'not checked',
            'update_available' => false,
            'message' => 'Update check is skipped during actions.',
            'update_url' => self::UPDATE_URL,
            'version_url' => self::VERSION_URL,
        ];
    }

    public static function loadUpdateCache(): ?array
    {
        if (!is_file(self::updateCacheFile())) {
            return null;
        }

        $decoded = json_decode((string) file_get_contents(self::updateCacheFile()), true);
        if (!is_array($decoded) || empty($decoded['checked_at']) || empty($decoded['status']) || !is_array($decoded['status'])) {
            return null;
        }

        $checkedAt = strtotime((string) $decoded['checked_at']);
        if (!$checkedAt || time() - $checkedAt > self::UPDATE_CACHE_TTL) {
            return null;
        }

        $status = $decoded['status'];
        $status['installed'] = self::VERSION;

        return $status;
    }

    public static function saveUpdateCache(array $status): array
    {
        self::ensureWritableDirs();
        $status['installed'] = self::VERSION;
        $cache = [
            'checked_at' => gmdate('c'),
            'status' => $status,
        ];

        if (is_dir(dirname(self::updateCacheFile())) && is_writable(dirname(self::updateCacheFile()))) {
            self::writeJson(self::updateCacheFile(), $cache);
        }

        return $status;
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
            'rate_limited' => 'Rate Limited',
            'api_error' => 'API Error',
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

    public static function statusFromHttpResponse(array $response): string
    {
        $statusCode = (int) ($response['status_code'] ?? 0);
        if ($statusCode === 429) {
            return 'rate_limited';
        }

        if ($statusCode === 503 || $statusCode === 0) {
            return 'api_unavailable';
        }

        return 'api_error';
    }

    public static function apiErrorMessage(array $response): string
    {
        $statusCode = (int) ($response['status_code'] ?? 0);
        if ($statusCode === 429) {
            return 'Rate limited: the Sernate Blocklist API received too many requests. Please wait and try again later.';
        }

        if ($statusCode === 503) {
            return 'API unavailable: the Sernate Blocklist API is temporarily unavailable. Please try again later.';
        }

        if ($statusCode === 0) {
            return 'API unavailable: could not connect to the Sernate Blocklist API.';
        }

        return 'API error: the Sernate Blocklist API returned HTTP ' . $statusCode . '.';
    }

    public static function safeHttpResponse(array $response): array
    {
        return [
            'ok' => (bool) ($response['ok'] ?? false),
            'status_code' => (int) ($response['status_code'] ?? 0),
            'error' => self::cleanHeaderValue((string) ($response['error'] ?? '')),
        ];
    }

    public static function safeUrl(?string $url): string
    {
        $url = trim((string) $url);
        if ($url === '') {
            return '';
        }

        $parts = parse_url($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return '';
        }

        return filter_var($url, FILTER_VALIDATE_URL) ? $url : '';
    }

    public static function humanTime(?string $value): string
    {
        $timestamp = strtotime((string) $value);
        if (!$timestamp) {
            return 'Never';
        }

        return date('Y-m-d H:i:s T', $timestamp);
    }

    public static function cleanHeaderValue(string $value): string
    {
        return trim(str_replace(["\r", "\n"], '', $value));
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
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
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

    public static function httpGet(string $url, string $accept = 'text/plain'): array
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
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => [
                'Accept: ' . self::cleanHeaderValue($accept),
                'User-Agent: Sernate-FireHOL-Blocklist-Check-DirectAdmin/' . self::VERSION,
            ],
        ]);
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }

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

    private static function recordResult(array $result, string $scope = 'server'): array
    {
        self::ensureWritableDirs();
        if ($scope !== 'manual') {
            self::writeJson(self::stateFile(), $result);
            self::updateIpCache($result);
        }
        self::recordDebug('run_check', [
            'scope' => $scope,
            'result_status' => $result['status'] ?? null,
            'result_message' => $result['message'] ?? null,
            'result_ips' => $result['ips'] ?? [],
            'runtime' => $result['debug'] ?? null,
        ]);

        return $result;
    }

    private static function updateIpCache(array $result): void
    {
        $checkedAt = (string) ($result['checked_at'] ?? gmdate('c'));
        $cache = self::loadIpCache();
        $rows = [];

        foreach (($result['api']['results'] ?? []) as $row) {
            if (!empty($row['ip'])) {
                $rows[(string) $row['ip']] = $row;
            }
        }

        foreach (($result['ips'] ?? []) as $ip) {
            $ip = (string) $ip;
            $row = $rows[$ip] ?? [];
            $cache[$ip] = [
                'checked_at' => $checkedAt,
                'status' => (string) ($result['status'] ?? ''),
                'currently_blacklisted' => !empty($row['currently_blacklisted']),
                'hits_count' => (int) ($row['hits_count'] ?? 0),
            ];
        }

        self::writeJson(self::ipCacheFile(), $cache);
    }

    private static function runtimeDebug(array $config, array $ips, ?array $response): array
    {
        return [
            'api_base_url' => $config['api_base_url'] ?? self::DEFAULT_API_BASE_URL,
            'current_only' => !empty($config['current_only']),
            'include_stale' => !empty($config['include_stale']),
            'detected_ips' => $ips,
            'http_status' => $response['status_code'] ?? null,
            'http_error' => self::cleanHeaderValue((string) ($response['error'] ?? '')),
            'ip_detection' => self::ipDetectionDebug(),
        ];
    }
}
