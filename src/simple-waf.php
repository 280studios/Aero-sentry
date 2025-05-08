<?php
// simple-waf.php - Simple WAF for Aero Sentry

include_once 'config.php';
if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

// --- Configuration ---

// Rate limiting
const RATE_LIMIT = 30; // Maximum requests per IP
const RATE_LIMIT_WINDOW = 10; // Rate limit window in seconds

// IP whitelisting and blacklisting
define('WHITELISTED_IPS', [
  '127.0.0.1',
  '::1'
]);

// Blacklisted IP's
/** Note: The blacklist is fetched from www.projecthoneypot.org */
$filePath = __DIR__ . '/data/ip-blacklist.txt';
$expectedHash = '32d40babdf290544ee7c93b6ec67f61c4f50ec1f4d9d257b366d97c9bfcf3d1a'; // Expected hash of the file (precomputed using sha256)
loadBlacklistedIPs($filePath, $expectedHash);

// Function to load and validate the blacklist IP file
function loadBlacklistedIPs(string $filePath, string $expectedHash): void {
  try {
    if (!file_exists($filePath)) {
      throw new Exception("Blacklist file not found: $filePath");
    }
  
    // Read the file contents
    $fileContents = file_get_contents($filePath);
    if ($fileContents === false) {
      throw new Exception("Failed to read the blacklist file: $filePath");
    }
  
    // Validate the file hash
    if (!empty($expectedHash) && !empty(HASH_ALGORITHM)) {
      $fileHash = hash(HASH_ALGORITHM, $fileContents);
      if ($fileHash !== $expectedHash) {
        throw new Exception("Blacklist file hash mismatch. Expected: $expectedHash, Found: $fileHash");
      }
    }

    // Parse the IP addresses into an array
    $ipAddresses = array_filter(array_map('trim', explode("\n", $fileContents)), function ($ip) {
      return filter_var($ip, FILTER_VALIDATE_IP);
    });
  
    if (empty($ipAddresses)) {
      if (!defined('BLACKLISTED_IPS')) {
        define('BLACKLISTED_IPS', []);
      }
      throw new Exception("No valid IP addresses found in the blacklist file.");
    }
  
    // Define the BLACKLISTED_IPS constant dynamically
    define('BLACKLISTED_IPS', $ipAddresses);
  } catch (Exception $e) {
    echo "Error: " . $e->getMessage();
  }
}

// Function to check if the IP address is rate-limited
function isRateLimited(string $ip): bool {
  $ip = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';

  if (!$ip) {
    return true;
  }
  // Check if the IP address is in the whitelist
  if (in_array($ip, WHITELISTED_IPS)) {
    return false;
  }
  // Check if the IP address is in the blacklist
  if (defined('BLACKLISTED_IPS') && in_array($ip, BLACKLISTED_IPS)) {
    handleBotDetected(false);
  }
  
  if (GDPR_COMPLIANT) {
    $ip = hash(HASH_ALGORITHM, $ip);
  }

  $key = "rate_limit_{$ip}";
  
  // Use APCu if available for in-memory caching
  if (function_exists('apcu_fetch') && function_exists('apcu_store') && function_exists('apcu_inc')) {
    $requests = apcu_fetch($key);
    if ($requests === false) {
      apcu_store($key, 1, RATE_LIMIT_WINDOW);
      return false;
    }
    if ($requests >= RATE_LIMIT) {
      return true;
    }
    apcu_inc($key);
    return false;
  }

  // Fallback to file-based cache if APCu is not available
  $tmp = sys_get_temp_dir();
  if (is_dir($tmp) && is_writable($tmp)) {
    // Make a subdirectory for rate limit caching
    $dir = $tmp . DIRECTORY_SEPARATOR . 'rate_limit_cache';
    if (!is_dir($dir)) {
      mkdir($dir);
    }
    if (is_writable($dir)) {
      $tmp = $dir;
    }

    $cacheFile = $tmp . DIRECTORY_SEPARATOR . $key;
    $currentTime = time();
    $data = file_exists($cacheFile) ? unserialize(file_get_contents($cacheFile)) : ['count' => 0, 'start_time' => $currentTime];

    if ($currentTime - $data['start_time'] > RATE_LIMIT_WINDOW) {
      $data = ['count' => 1, 'start_time' => $currentTime];
    } else {
      if ($data['count'] >= RATE_LIMIT) {
        return true;
      }
      $data['count']++;
    }
    file_put_contents($cacheFile, serialize($data));
    return false;
  }

  return false;
}

?>