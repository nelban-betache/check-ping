<?php
// secure-netcheck.php
// Single-file secure network check tool
// INSTALL: place this file on a PHP-enabled server (PHP 7.4+ recommended)
// USAGE: open in browser, enter host (IP or hostname) and port, then click Check.

// -------- CONFIG --------
// Basic HTTP auth credentials (change before deploying)
$AUTH_USER = 'admin';
$AUTH_PASS = 'ChangeMe123!';

// Rate limiting: max requests per IP in the time window
$RATE_LIMIT_MAX = 12; // max requests
$RATE_LIMIT_WINDOW = 60; // seconds

// Where to store rate-limit data (must be writable)
$RATE_DIR = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'netcheck_rl';

// Allow optional shell ping? default: disabled for safety. Enable only if you trust environment.
$ALLOW_SHELL_PING = false;
// ------------------------

// Ensure rate dir exists
if (!is_dir($RATE_DIR)) {
    @mkdir($RATE_DIR, 0700, true);
}

// Basic HTTP auth (simple, but better than none)
if (!isset($_SERVER['PHP_AUTH_USER']) ||
    $_SERVER['PHP_AUTH_USER'] !== $AUTH_USER ||
    !isset($_SERVER['PHP_AUTH_PW']) ||
    $_SERVER['PHP_AUTH_PW'] !== $AUTH_PASS) {
    header('WWW-Authenticate: Basic realm="NetCheck"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Authentication required.';
    exit;
}

// Rate limiting by IP (file-based token bucket)
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rl_file = $RATE_DIR . DIRECTORY_SEPARATOR . md5($client_ip) . '.json';
$now = time();
$remaining = true;

if (file_exists($rl_file)) {
    $data = json_decode(@file_get_contents($rl_file), true) ?: ['count'=>0,'ts'=>$now];
    // reset window if expired
    if ($now - $data['ts'] > $RATE_LIMIT_WINDOW) {
        $data = ['count'=>0,'ts'=>$now];
    }
} else {
    $data = ['count'=>0,'ts'=>$now];
}

$data['count']++;
file_put_contents($rl_file, json_encode($data));
if ($data['count'] > $RATE_LIMIT_MAX) {
    http_response_code(429);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Rate limit exceeded. Try again later.\n";
    exit;
}

// Helper: safe output
function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// Handle form input
$results = '';
if (isset($_GET['host']) && isset($_GET['port'])) {
    $raw_host = trim((string)$_GET['host']);
    $port = (int)($_GET['port']);
    $timeout = isset($_GET['timeout']) ? max(1, (int)$_GET['timeout']) : 3;
    $do_shell_ping = isset($_GET['ping']) && $_GET['ping'] && $ALLOW_SHELL_PING;

    // Basic validation: host can be IP or hostname
    $is_ip = filter_var($raw_host, FILTER_VALIDATE_IP);
    $is_hostname = (bool)preg_match('/^[a-zA-Z0-9.-]{1,253}$/', $raw_host);

    if (!$is_ip && !$is_hostname) {
        $results = "Invalid host or IP. Only IPv4/IPv6 or hostname characters allowed.\n";
    } elseif ($port < 1 || $port > 65535) {
        $results = "Invalid port. Use 1-65535.\n";
    } else {
        // Resolve DNS for hostname (or return IP for IP input)
        $resolved = [];
        if ($is_ip) {
            $resolved[] = $raw_host;
        } else {
            // gethostbynamel returns array of IPv4 or false. For IPv6, use dns_get_record
            $a = @gethostbynamel($raw_host);
            if ($a && is_array($a)) {
                foreach ($a as $ip) $resolved[] = $ip;
            }
            // try AAAA
            $aaaa = dns_get_record($raw_host, DNS_AAAA);
            if ($aaaa) {
                foreach ($aaaa as $rec) if (!empty($rec['ipv6'])) $resolved[] = $rec['ipv6'];
            }
            $resolved = array_values(array_unique($resolved));
        }

        if (count($resolved) === 0) {
            $results .= "DNS resolution failed for " . h($raw_host) . "\n";
        } else {
            $results .= "Resolved addresses for " . h($raw_host) . ":\n";
            foreach ($resolved as $ip) $results .= " - " . h($ip) . "\n";
        }

        // Attempt TCP connection to port for each resolved IP until one succeeds (or try direct host for IP)
        $connected = false;
        $conn_messages = [];
        foreach ($resolved as $ip) {
            $start = microtime(true);
            // Use @ to suppress warnings; handle failure via return value
            $fp = @fsockopen($ip, $port, $errno, $errstr, $timeout);
            $elapsed = round(microtime(true) - $start, 3);
            if ($fp) {
                fclose($fp);
                $conn_messages[] = "Connection to {$ip}:{$port} succeeded ({$elapsed}s)";
                $connected = true;
                // don't break — collect all successes
            } else {
                $conn_messages[] = "Connection to {$ip}:{$port} failed: " . h($errstr) . " ({$errno})";
            }
        }
        if (empty($resolved)) {
            // if resolution empty but user supplied IP, still try host directly
            $start = microtime(true);
            $fp = @fsockopen($raw_host, $port, $errno, $errstr, $timeout);
            $elapsed = round(microtime(true) - $start, 3);
            if ($fp) { fclose($fp); $conn_messages[] = "Connection to {$raw_host}:{$port} succeeded ({$elapsed}s)"; $connected=true; }
            else { $conn_messages[] = "Connection to {$raw_host}:{$port} failed: " . h($errstr) . " ({$errno})"; }
        }

        $results .= "\nTCP check results:\n" . implode("\n", $conn_messages) . "\n";

        // Optionally run a safe ping via shell ONLY if explicitly allowed in config
        if ($do_shell_ping) {
            // Use escapeshellarg to prevent injection. Only allow simple numeric count.
            $count = 3;
            $safe_target = escapeshellarg($raw_host);
            $flag = (stripos(PHP_OS_FAMILY, 'Windows') === 0) ? '-n' : '-c';
            $cmd = "ping {$flag} {$count} {$safe_target} 2>&1";
            $results .= "\nShell ping output (sanitized):\n";
            $out = shell_exec($cmd);
            $results .= $out !== null ? $out : "(no output)\n";
        }

        // Provide a short note about security
        $results .= "\nNote: This tool uses PHP to open sockets from the server. Results reflect server network path, not your client device.\n";
    }
}

?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Secure NetCheck</title>
  <!-- Tailwind CDN for quick styling (optional) -->
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen p-6">
  <div class="max-w-3xl mx-auto bg-white shadow-md rounded-2xl p-6">
    <h1 class="text-2xl font-semibold mb-2">Secure NetCheck Diagnostic Tool</h1>
    <p class="text-sm text-gray-600 mb-4">Authenticated, rate-limited tool — resolves DNS, attempts TCP connect, and optionally runs a safe ping if enabled on server.</p>

    <form method="GET" class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
      <div class="sm:col-span-2">
        <label class="block text-sm font-medium">Host (IP or hostname)</label>
        <input class="mt-1 block w-full rounded-md border px-3 py-2" name="host" required value="<?php echo isset($raw_host) ? h($raw_host) : ''; ?>">
      </div>
      <div>
        <label class="block text-sm font-medium">Port</label>
        <input class="mt-1 block w-full rounded-md border px-3 py-2" name="port" type="number" min="1" max="65535" required value="<?php echo isset($port) ? (int)$port : 80; ?>">
      </div>

      <div class="sm:col-span-2">
        <label class="inline-flex items-center mt-2">
          <input type="checkbox" name="ping" class="mr-2" <?php echo (isset($_GET['ping']) && $_GET['ping']) ? 'checked' : ''; ?> <?php echo $ALLOW_SHELL_PING ? '' : 'disabled'; ?>>
          <span class="text-sm">Run server-side ping (<?php echo $ALLOW_SHELL_PING ? 'allowed' : 'disabled'; ?>)</span>
        </label>
      </div>

      <div class="sm:col-span-3 text-right">
        <button class="mt-2 px-4 py-2 rounded-md bg-blue-600 text-white">Check</button>
      </div>
    </form>

    <div class="bg-gray-100 rounded-md p-3 font-mono text-sm whitespace-pre-wrap h-64 overflow-auto">
      <?php if ($results !== ''): ?>
        <?php echo nl2br(h($results)); ?>
      <?php else: ?>
        <?php echo "Enter host and port, then click Check.\n"; ?>
      <?php endif; ?>
    </div>

    <div class="mt-4 text-xs text-gray-500">
      <strong>Deploy notes:</strong>
      <ul class="list-disc ml-5">
        <li>Edit <code>\$AUTH_USER</code> and <code>\$AUTH_PASS</code> before public deployment.</li>
        <li>Set <code>\$ALLOW_SHELL_PING = true</code> only if you trust the server environment — shell ping is disabled by default for safety.</li>
        <li>For production, replace basic auth with proper application auth, use HTTPS, and consider storing rate-limit data in Redis/DB.</li>
      </ul>
    </div>
  </div>
</body>
</html>
