<?php

// Server Host
const DOMAIN = 'localhost';  // Change to your domain name or IP address
define('HOST', DOMAIN ?? $_SERVER['SERVER_NAME']);

// Files
define('ERROR_LOG_FILE', __DIR__ . '/data/error.log');
define('USER_AGENT_FILE', __DIR__ . '/data/user-agents.json');
define('DB_FILE', __DIR__ . '/data/client_metadata.db');  // [Optional] Database settings

// General settings
const DEBUG = false;

// PoW settings
/** Note: the DIFFICULTY value is exponential. */
const DEFAULT_DIFFICULTY = 3; // Default PoW difficulty
const HIGH_DIFFICULTY = 6; // Difficulty for high server load
const BOT_DIFFICULTY = 8;  // Difficulty for Bots.
const HIGH_LOAD_THRESHOLD = 1.0; // Server load threshold for increasing difficulty - Uses sys_getloadavg()
const CHALLENGE_EXPIRY_TIME = 300; // 5 minutes

// Security settings
const HASH_ALGORITHM = 'sha256';  // Globally used hash algorithm
const CSRF_TOKEN_LENGTH = 32;

// Privacy settings
const GDPR_COMPLIANT = true; // Encrypts IP address at rest if true

// Client metadata settings
const CLIENT_METADATA_ENABLED = false;
define('CLIENT_METADATA_MAX_SIZE', 1024 * 1024); // 1 MB

// Client metadata input field whitelist
define('CLIENT_METADATA_WHITELIST', [
  'userAgent',
  'language',
  'webgl',
  'webGLSupported',
  'languages',
  'rtt',
  'screen',
  'touchPoints',
  'cookieEnabled',
  'browserType',
  'platform',
  'language',
  'isMobile'
]);

// Debug on/off
if(DEBUG) {
  error_reporting(E_ALL);
  ini_set("display_errors", 1);
  ini_set('display_startup_errors', 1);
  
  if (!file_exists(ERROR_LOG_FILE)) {
    touch(ERROR_LOG_FILE);
  }
  ini_set('error_log', ERROR_LOG_FILE);
} else {
  error_reporting(0);
  ini_set("display_errors", 0);
  ini_set('display_startup_errors', 0);
}

// Session settings
ini_set('session.use_only_cookies', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.use_trans_sid', 0);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_lifetime', CHALLENGE_EXPIRY_TIME);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.gc_maxlifetime', 0);
ini_set('session.cookie_domain', HOST);
ini_set('session.hash_function', HASH_ALGORITHM);

// Timezone & encoding
date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Global Headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: ' . DOMAIN);
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
