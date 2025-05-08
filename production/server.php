<?php
require_once 'config.php';

header('Content-Type: application/json');
header('Referrer-Policy: no-referrer');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type, Authorization, Accept');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: ' . CHALLENGE_EXPIRY_TIME);

session_start();
session_regenerate_id(true);

// Error logging function
function logError($message) {
  if (empty($message)) {
    $message = 'Unknown error';
  }
  error_log($message . ' @' . date('Y-m-d H:i:s') . PHP_EOL, 3, ERROR_LOG_FILE);
}

function handlePostErrors($e) {
  $data = [];
  $data["success"] = false;
  $data["error"] = $e->getMessage();

  if (DEBUG) logError($e->getMessage());

  if ($e->getCode() === 1) {  // Use error code for specific reload cases
    $data["reload"] = true;
    jsonResponse(200, $data);
    return;
  } else {
    jsonResponse(200, $data); // Error response
  }
}

// Sanitize user input function
function sanitizeInput(string $data): string {
  return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES);
}

// Json Response function
function jsonResponse($status = 200, $data = []) {
  if ($status > 299) {
    logError(json_encode($data, JSON_PRETTY_PRINT));
  }

  header('Content-Type: application/json; charset=utf-8');
  http_response_code($status);
  echo json_encode($data);
  exit();
}

// Main - Handle Requests
try {
  // Main request handler logic
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(405, ["error" => "Method not allowed."]);
  }

  $input = json_decode(file_get_contents('php://input'), true);
  if (json_last_error() !== JSON_ERROR_NONE) {
    jsonResponse(400, ["error" => "Invalid JSON payload."]);
  }

  if (empty($input)) {
    jsonResponse(400, ["error" => "Empty input."]);
  }

  if (isset($input['nonice'])) {
    initializeSession($input);
  } elseif (isset($input['nonce'])) {
    verifyPoWSubmission($input);
  } elseif (isset($input['checkboxClicked'], $input['interacted'])) {
    handleCheckboxClick($input['checkboxClicked'], $input['interacted']);
  }

  jsonResponse(400, ["error" => "Invalid request."]);
} catch (Exception $e) {
  resetCsrfToken();
  jsonResponse(500, ["error" => $e->getMessage()]);
}

// Handle a new connection request
function initializeSession($input): void {
  if (empty($input)) throw new Exception('Missing relevant data.', 1);

  try {
    $jsBotDetected = false;

    // Ensure the nonice is correctly formatted
    if (!isset($input['nonice']) || !preg_match('/^[a-f0-9]{20}$/', $input['nonice'])) {
      throw new Exception('Invalid token, please reload the page.', 1);
    }

    // Process client information
    if (CLIENT_METADATA_ENABLED) {
      if (!isset($_SESSION['client_info'])) {
        // Collect browser components data
        if (isset($input['browserComponents'])) {
          // Check if the data exceeds the maximum allowed size
          $clientDataSize = strlen(json_encode($input['browserComponents']));
          if ($clientDataSize > CLIENT_METADATA_MAX_SIZE) {
            throw new Exception('Client metadata size exceeds the maximum allowed size.', 1);
          }

          $clientData = processClientInfo($input['browserComponents']);
          if ($clientData) {
            $_SESSION['client_info'] = $clientData;
          } else {
            throw new Exception('Missing relevant data.', 1);
          }
        } else {
          logError('Missing relevant data. (maybe enableClientDataCollection is false in config.php or js and enabled in the other.)');
        }
      } elseif (isset($input['collectDataFailed']) && $input['collectDataFailed'] === true) {
        // Handle the case where data collection failed but is enabled
        $jsBotDetected = true;  // Set the bot detection flag to true
        logError('Data collection failed from client -> browserDetector.');
      }
    }

    // Get if the client is a bot
    $jsBotDetected = $input['detectionResult']['isBot'] ?? false;
    
    // Generate and send a new challenge
    respondWithChallenge($jsBotDetected);
  } catch (Exception $e) {
    handlePostErrors($e);
  }
}

// Generate and store a new challenge, difficulty, CSRF token, and expiry time
function respondWithChallenge($jsBotDetected = false): void {
  // Reset the challenge and CSRF token
  resetChallenge();
  resetCsrfToken();

  $botOutcome = false;
  $challenge = generateChallenge(16);
  $csrfToken = generateCsrfToken();
  $botOutcome = $jsBotDetected ? true : false;
  $difficulty = $botOutcome ? BOT_DIFFICULTY : adjustDifficulty();

  $_SESSION['challenge'] = $challenge;
  $_SESSION['csrfToken'] = $csrfToken;
  $_SESSION['difficulty'] = $difficulty;
  $_SESSION['challenge_expiry'] = time() + CHALLENGE_EXPIRY_TIME;

  // Respond with the challenge, difficulty, and CSRF token
  $data = [
    "challenge" => $challenge,
    "csrfToken" => $csrfToken,
    "difficulty" => $difficulty,
    "threshold" => HIGH_DIFFICULTY
  ];

  header('Cache-Control: no-cache');
  jsonResponse(200, $data);
  exit();
}

// PoW solution submission
function verifyPoWSubmission(array $input): void {
  try {
    if (empty($input)) {
      throw new Exception('Invalid input.');
    }
    $challenge = $_SESSION['challenge'] ?? null;
    $nonce = $input['nonce'] ?? '';
    $difficulty = $_SESSION['difficulty'] ?? DEFAULT_DIFFICULTY;
    $timestamp = $_SESSION['challenge_expiry'] ?? time()-100;

    if (!validateCsrfToken()) {
      throw new Exception('Invalid token, please reload the page.', 1);
    }

    if (!$challenge || !$nonce) {
      resetChallenge();
      throw new Exception('Challenge expired. Please reload the page.', 1);
    }

    if (!$timestamp || $timestamp < time()) {
      resetChallenge();
      throw new Exception('Challenge expired. Please reload the page.', 1);
    }

    if (!verifyPoW($challenge, $nonce, $difficulty)) {
      resetChallenge();
      throw new Exception('Invalid proof of work.', 1);
    }

    // Verify client metadata
    $crazyScore = verifyClientMetadata();
    // Handle bot detection outcome
    if ($crazyScore >= 4) {
      handleBotDetected(false);
      throw new Exception('Bot detected.');
    }

    resetChallenge();
    setChallengePassed();
    jsonResponse(201, ["success" => true, "reload" => false]); // Success response
  } catch (Exception $e) {
    handlePostErrors($e);
  }
}

// Handle checkbox click event
function handleCheckboxClick(bool $checkboxClicked, bool $interacted): void {
  try {
    if (!validateCsrfToken()) {
      throw new Exception('Invalid token, please reload the page.', 1);
    }
    if (!isChallengePassedValid()) {
      resetChallenge();
      throw new Exception('Challenge expired. Please reload the page.', 1);
    }
    if (empty($interacted)) {
      throw new Exception('Invalid interaction. Please reload the page.', 1);
    }
    if (!isset($checkboxClicked) || $checkboxClicked !== true) {
      throw new Exception('Invalid checkbox state. Please reload the page.', 1);
    }

    if ($checkboxClicked) {
      resetChallenge();
      jsonResponse(201, ["success" => true]);
    }
  } catch (Exception $e) {
    handlePostErrors($e);
  }
}

// Function to get the Authorization header
function getAuthorizationHeader() {
  if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
    return $_SERVER['HTTP_AUTHORIZATION'];
  } elseif (function_exists('getallheaders')) {
    $headers = getallheaders();
    return $headers['Authorization'] ?? null;
  }
  return null;
}

/** CSRF token validation & generation */

// Validate the CSRF token
function validateCsrfToken(): bool {
  $authHeader = getAuthorizationHeader();
  if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    return false;
  }
  $receivedCsrfToken = $matches[1];
  if (!isset($_SESSION['csrfToken'], $_SESSION['csrfToken_expiry']) || $_SESSION['csrfToken_expiry'] < time()) {
    resetCsrfToken();
    return false;
  }
  if (!hash_equals($_SESSION['csrfToken'], $receivedCsrfToken)) {
    resetCsrfToken();
    return false;
  }
  return true;
}

// Generate a CSRF token for security
function generateCsrfToken(): string {
  $csrfToken = bin2hex(random_bytes(CSRF_TOKEN_LENGTH));
  $_SESSION['csrfToken'] = $csrfToken;
  $_SESSION['csrfToken_expiry'] = time() + CHALLENGE_EXPIRY_TIME;
  return $csrfToken;
}

// Reset the CSRF token
function resetCsrfToken(): void {
  unset($_SESSION['csrfToken'], $_SESSION['csrfToken_expiry']);
}

/** Challenge generation and validation */

// Generate a unique challenge for the client
function generateChallenge(int $bytes = 16): string {
  $timestamp = microtime(true);
  $randomValue = bin2hex(random_bytes($bytes));
  $hash = hash(HASH_ALGORITHM, $timestamp . $randomValue);
  return $hash;
}

// Set the challenge as passed and set the expiry time
function setChallengePassed(): void {
  $_SESSION['challenge_passed'] = true;
  $_SESSION['challenge_passed_expiry'] = time() + CHALLENGE_EXPIRY_TIME;
}

// Check if the challenge has been passed and is still valid
function isChallengePassedValid(): bool {
  if (!isset($_SESSION['challenge_passed'], $_SESSION['challenge_passed_expiry']) || $_SESSION['challenge_passed_expiry'] < time()) {
    resetChallengePassed();
    return false;
  }
  return true;
}

// Reset the challenge, CSRF token, difficulty, and expiry time
function resetChallenge(): void {
  unset($_SESSION['challenge'], $_SESSION['difficulty'], $_SESSION['challenge_expiry']);
}

function resetChallengePassed(): void {
  unset($_SESSION['challenge_passed'], $_SESSION['challenge_passed_expiry']);
}

// Dynamic difficulty adjustment based on server load and suspicion score
function adjustDifficulty($suspicionScore = 0): int {
  $serverLoad = sys_getloadavg()[0];
  $baseDifficulty = ($serverLoad > HIGH_LOAD_THRESHOLD) ? HIGH_DIFFICULTY : DEFAULT_DIFFICULTY;

  // Increase difficulty based on suspicion
  if ($suspicionScore > 5) {
    $baseDifficulty += 3; // Significant increase
  } elseif ($suspicionScore > 2) {
    $baseDifficulty += 1; // Moderate increase
  }

  return $baseDifficulty;
}

// Verify the proof of work submitted by the client
function verifyPoW(string $challenge, string $nonce, int $difficulty): bool {
  $hash = hash(HASH_ALGORITHM, $challenge . $nonce);
  return substr($hash, 0, $difficulty) === str_repeat('0', $difficulty);
}

// Handle bot detection
function handleBotDetected($json = false): void {
  $_SESSION['bot_detected'] = true;
  
  if ($json) {
    jsonResponse(403, ["success" => false, "reload" => true]);
  } else {
    header('HTTP/1.1 403 Forbidden');
    die();
  }
}

// Process client information
function processClientInfo($input): array {
  if (empty($input)) {
    return [];
  }

  $fields = CLIENT_METADATA_WHITELIST;
  $clientInfo = [];

  foreach ($fields as $field) {
    $clientInfo[$field] = $input[$field] ?? '';
  }
  return $clientInfo;
}

// Verify client metadata on server
function verifyClientMetadata() {
  $dataAnomaly = 0;
  $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
  $user_lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 5) : '';
  $http_accept = $_SERVER['HTTP_ACCEPT'] ?? '';

  // IP Test
    if (!filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
      $dataAnomaly += 2;
    }
  // User Agent Test
    if (isset($_SESSION['client_info']['userAgent'], $user_agent)) {
      if ($user_agent !== $_SESSION['client_info']['userAgent']) {
        $dataAnomaly += 1;
      }
      // User-agent string match from json file.
      if (isUserAgentBot($user_agent)) {
        $dataAnomaly += 1;
      }
    }
  // Language Test
    if (isset($_SESSION['client_info']['language'], $user_lang)) {
      if ($user_lang !== $_SESSION['client_info']['language']) {
        $dataAnomaly += 1;
      }
    } elseif (empty($user_lang)) {
      $dataAnomaly += 1;
    }
  // Accept Test
    if (empty($http_accept)) {
      $dataAnomaly += 1;
    }

  writeClientMetadataToDatabase();  // [Optional]

  return $dataAnomaly;
}

// Function to get the bot names from user-agents.json
function getSuspiciousUserAgents() {
  $userAgentFile = USER_AGENT_FILE;
  if (file_exists($userAgentFile)) {
    $userAgentData = json_decode(file_get_contents($userAgentFile), true);
    if (is_array($userAgentData)) {
      return $userAgentData;
    }
  }
  return [];
}

function isUserAgentBot($user_agent) {
  if (empty($user_agent) || !is_string($user_agent)) {
    logError("Invalid user agent string: $user_agent");
    return true;
  }

  $userAgentData = getSuspiciousUserAgents();
  if (empty($userAgentData) || !is_array($userAgentData)) {
    logError('Failed to load user-agent data from JSON file.');
    return false;
  }

  $suspiciousAgents = $userAgentData['suspiciousAgents'] ?? [];
  $crawlerBots = $userAgentData['crawlerBots'] ?? [];
  $goodUserAgents = $userAgentData['goodUserAgents'] ?? [];
  $combinedList = array_merge($suspiciousAgents, $crawlerBots);

  foreach ($goodUserAgents as $goodUA) {
    if (preg_match("/$goodUA/i", $user_agent)) {
      return false;  // It's a known good UA, so not a bot
    }
  }

  $botRegex = '/' . implode('|', $combinedList) . '/i';
  if (preg_match($botRegex, $user_agent)) {
    return true;
  }

  return false;
}

// [Optional] Function to write client metadata to the database
function writeClientMetadataToDatabase() {
  if (!isset($_SESSION['client_info']) || empty($_SESSION['client_info'])) return false;
  if (!CLIENT_METADATA_ENABLED) return false;

  $clientData = $_SESSION['client_info'];
  $ip = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP) ? $_SERVER['REMOTE_ADDR'] : '';

  if (GDPR_COMPLIANT) {
    // Anonymize IP address
    $ip = !empty($ip) ? hash(HASH_ALGORITHM, $ip) : $ip;
    $clientData['ip'] = !empty($clientData['ip']) ? hash(HASH_ALGORITHM, $clientData['ip']) : $ip;
  }
  
  // Check if any value is empty
  foreach ($clientData as $key => $value) {
    if (!isset($value) || empty($value)) {
      $clientData[$key] = '';
    }
  }
  
  try {
    if (!extension_loaded('sqlite3')) {
      throw new Exception('SQLite3 extension is not enabled.');
    }

    $db = new SQLite3(DB_FILE);
  
    // Create table if it doesn't exist
    $db->exec('
      CREATE TABLE IF NOT EXISTS client_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_agent TEXT,
        language TEXT,
        webgl_vendor TEXT,
        webgl_renderer TEXT,
        webGLSupported INTEGER,
        languages TEXT,
        rtt TEXT,
        screen_width INTEGER,
        screen_height INTEGER,
        screen_outer_width INTEGER,
        screen_outer_height INTEGER,
        touchPoints INTEGER,
        cookieEnabled INTEGER,
        browserType TEXT DEFAULT "Unknown",
        platform TEXT,
        mobile BOOLEAN DEFAULT 0,
        ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    ');
    
    // Insert client metadata into table
    $stmt = $db->prepare('
      INSERT INTO client_metadata (
        user_agent,
        language,
        webgl_vendor,
        webgl_renderer,
        webGLSupported,
        languages,
        rtt,
        screen_width,
        screen_height,
        screen_outer_width,
        screen_outer_height,
        touchPoints,
        cookieEnabled,
        browserType,
        platform,
        mobile,
        ip
      ) VALUES (
        :user_agent,
        :language,
        :webgl_vendor,
        :webgl_renderer,
        :webGLSupported,
        :languages,
        :rtt,
        :screen_width,
        :screen_height,
        :screen_outer_width,
        :screen_outer_height,
        :touchPoints,
        :cookieEnabled,
        :browserType,
        :platform,
        :mobile,
        :ip
      );
    ');
    
    $stmt->bindValue(':user_agent', $clientData['userAgent']);
    $stmt->bindValue(':language', $clientData['language']);
    $stmt->bindValue(':webgl_vendor', $clientData['webgl']['vendor']);
    $stmt->bindValue(':webgl_renderer', $clientData['webgl']['renderer']);
    $stmt->bindValue(':webGLSupported', $clientData['webGLSupported']);
    $stmt->bindValue(':languages', implode(',', $clientData['languages']));
    $stmt->bindValue(':rtt', $clientData['rtt']);
    $stmt->bindValue(':screen_width', $clientData['screen']['width']);
    $stmt->bindValue(':screen_height', $clientData['screen']['height']);
    $stmt->bindValue(':screen_outer_width', $clientData['screen']['outerWidth']);
    $stmt->bindValue(':screen_outer_height', $clientData['screen']['outerHeight']);
    $stmt->bindValue(':touchPoints', $clientData['touchPoints']);
    $stmt->bindValue(':cookieEnabled', $clientData['cookieEnabled']);
    $stmt->bindValue(':browserType', $clientData['browserType'] ?? 'Unknown');
    $stmt->bindValue(':platform', $clientData['platform']);
    $stmt->bindValue(':mobile', $clientData['isMobile'] ?? 0);  // ? 1 : 0
    $stmt->bindValue(':ip', $clientData['ip'] ?? $_SERVER['REMOTE_ADDR']);
    
    $result = $stmt->execute();
    
    $db->close();

    if (!$result) {
      logError('Error writing client metadata to database: ' . $db->lastErrorMsg());
      return false;
    }
    
    return true;
  } catch (Exception $e) {
    logError('Error writing client metadata to database: ' . $e->getMessage());
    return false;
  }
}
?>