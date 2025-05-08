(function() {  // IIFE for encapsulation
  "use strict";

  // --- Configuration (can be overridden by the host page) ---
  const config = {
    serverUrl: './server.php', // Replace with your actual server URL
    endPoint: 'success.php',
    userAgentsFile: 'data/user-agents.json',
    enableClientDataCollection: false, // Send client info to server for analysis
    showLoadingScreen: true,  // Show the loading screen UI (detection still runs)
    anomaliesCountLimit: 3, // Anomalies limit until the request is blocked
    debug: false,
  };

  // --- Global Variables ---
  let csrfToken = '';
  let difficulty = 3;
  let challenge = '';
  let threshold = 4;

  let userInteracted = false;

  // --- SSL ---
  if (window.location.protocol !== 'https:') {
    config.enableClientDataCollection = false;
    console.warn('Warning: Server URL should be HTTPS! Data collection will be disabled.');
  }

  // --- Helper Functions ---
  const log = (...args) => {
    if (config.debug) {
      console.log(...args);
    }
  };

  const errorLog = (...args) => {
    if (config.debug) {
      console.error(...args);
    }
  };

  // --- browser detection logic (START) ---

  // Collects detailed browser information
  const collectData = () => {
    const data = {
      userAgent: navigator.userAgent || '',
      language: navigator.language || navigator.userLanguage || '',
      webgl: { vendor: '', renderer: '' },
      webGLSupported: false,
      languages: [],
      rtt: navigator.connection ? navigator.connection.rtt : null,
      screen: {
        width: window.innerWidth,
        height: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight
      },
      touchPoints: navigator.msMaxTouchPoints || navigator.maxTouchPoints || 0,
      cookieEnabled: navigator.cookieEnabled,
      browserType: getBrowserKind(navigator.userAgent),
      platform: navigator.platform || ''
    };

    // Get WebGL information
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl');

      if (gl) {
        data.webgl.vendor = gl.getParameter(gl.VENDOR);
        data.webgl.renderer = gl.getParameter(gl.RENDERER);
        data.webGLSupported = true;

        // More WebGL parameters, if needed for further server-side analysis
        /*data.webgl.version = gl.getParameter(gl.VERSION);
        data.webgl.shadingLanguageVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
        data.webgl.supportedExtensions = gl.getSupportedExtensions(); // Array of extensions
        */
      }
    } catch (e) {}

    // Get supported languages
    try {
      data.languages = Array.isArray(navigator.languages) ? navigator.languages.slice(0, 3) : [navigator.language];
    } catch (e) {}

    return data;
  };

  // Utility function to count truthy values
  const countTruthy = (values) => values.filter(Boolean).length;

  // Browser engine detection
  const getBrowserEngineKind = () => {
    const n = navigator, w = window;

    if (countTruthy([
      'webkitPersistentStorage' in n,
      'webkitTemporaryStorage' in n,
      'webkitResolveLocalFileSystemURL' in w,
      'BatteryManager' in w,
      'webkitMediaStream' in w,
      'webkitSpeechGrammar' in w,
    ]) >= 5) return 'Chromium';

    if (countTruthy([
      'ApplePayError' in w,
      'CSSPrimitiveValue' in w,
      'Counter' in w,
      'getStorageUpdates' in n,
      'WebKitMediaKeys' in w,
    ]) >= 4) return 'Webkit';

    if (countTruthy([
      'buildID' in n,
      'MozAppearance' in (document.documentElement?.style ?? {}),
      'onmozfullscreenchange' in w,
      'mozInnerScreenX' in w,
      'CSSMozDocumentRule' in w,
      'CanvasCaptureMediaStream' in w,
    ]) >= 4) return 'Gecko';

    return 'Unknown';
  };

  // Browser type detection
  const getBrowserKind = (userAgent) => {
    userAgent = userAgent.toLowerCase();
    if (userAgent.includes('edg/')) return 'Edge';
    if (userAgent.includes('trident') || userAgent.includes('msie')) return 'IE';
    if (userAgent.includes('firefox')) return 'Firefox';
    if (userAgent.includes('chrome') && !userAgent.includes('edg/') && !userAgent.includes('opr')) return 'Chrome';
    if (userAgent.includes('chromium')) return 'Chromium';
    if (userAgent.includes('safari') && !userAgent.includes('chrome')) return 'Safari';
    if (userAgent.includes('opera') || userAgent.includes('opr')) return 'Opera';
    if (userAgent.includes('wechat')) return 'WeChat';
    if (userAgent.includes('brave')) return 'Brave';
    if (userAgent.includes('vivaldi')) return 'Vivaldi';
    if (userAgent.includes('yandex')) return 'Yandex';
    return 'Unknown';
  };

  // Suspicious User-Agent detection
  const suspiciousUA = async (userAgent, allowGoodBots = true) => {
    userAgent = userAgent.toLowerCase();
    let data = {};

    try {
      const response = await fetch(config.userAgentsFile, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        }
      });

      if (response.ok) {
        data = await response.json();
        if (!data || !Array.isArray(data.suspiciousAgents) || !Array.isArray(data.crawlerBots)) {
          throw new Error('Invalid user-agents.json format.');
        }
      } else {
        // Use backup if fetching user-agents.json fails
        data = {
          "suspiciousAgents": [
            "curl", "perl", "python", "java", "bot", "crawl", "puppeteer", "puppet",
            "phantomjs", "awesomium", "electron", "headlesschrome", "slimerjs"
          ], "crawlerBots": []
        };

        log('Failed to fetch user-agents.json, using backup.');
      }

      const suspiciousAgents = data.suspiciousAgents || [];
      const crawlerBots = data.crawlerBots || [];
      const combinedList = allowGoodBots ? [...suspiciousAgents, ...crawlerBots] : suspiciousAgents;
      const result = combinedList.filter(botUA => userAgent.includes(botUA));

      if (result.length > 0) {
        return result[0];
      }
      return false;

    } catch (error) {
      errorLog('Error loading or processing user-agents.json:', error);
      return false; // Or handle the error as appropriate
    }
  };

  // Checks if browser user-agent matches expected engine
  const isBrowserEngineValid = (data) => {
    const browser = getBrowserKind(data.userAgent);
    const engine = getBrowserEngineKind();

    const validPairs = {
      'Firefox': 'Gecko',
      'Chrome': 'Chromium',
      'Edge': 'Chromium',
      'Safari': 'Webkit',
      'Opera': 'Chromium',
      'Brave': 'Chromium',
      'Vivaldi': 'Chromium',
      'Yandex': 'Chromium',
      'WeChat': 'Chromium'
    };

    return validPairs[browser] === engine;
  };
  // Checks WebGL vendor and renderer values
  const isWebGLVerified = (data) => {
    const expectedWebGL = {
      'Mozilla': 'Mozilla',
      'Google Inc.': /ANGLE/i,
      'Apple': /WebKit/i,
      'Samsung': /Samsung/i,
      'Brave Software': /ANGLE/i,
      'Yandex': /ANGLE/i,
      'Vivaldi Technologies': /ANGLE/i,
      'WebKit': 'WebKit WebGL',
    };

    return expectedWebGL[data.webgl.vendor] === data.webgl.renderer;
  };

  // Checking mobile user-agent
  const isMobileUserAgent = (userAgent, touchPoints, screen) => {
    userAgent = userAgent.toLowerCase();

    if (touchPoints < 1) {
      return false;
    }

    if (/android|; wv/i.test(userAgent)) return true;
    if (/iphone|safari/i.test(userAgent)) return true;
    if (/samsung/i.test(userAgent)) return true;
    if (/huawei/i.test(userAgent)) return true;
    if (/tablet|kindle|ipad/i.test(userAgent)) return true; // Check for tablets
    if (/(midp|mmp|mobile|sonyericsson|webos|xda)/i.test(userAgent)) return true;

    // Check vertical screen. INACURATE!
    if (screen) {
      if (screen.width < screen.height) return true;
    }

    return false;
  };

  // Main bot detection function
  const detectBot = async (data) => {
    const detection = {
      isBot: false,
      detectedBotKind: 'unknown',
      anomalies: []
    };

    const isHeadless = () => {
      return (
        data.userAgent.includes('HeadlessChrome') ||
        navigator.webdriver ||
        !navigator.languages ||
        navigator.languages.length === 0 ||
        window.outerWidth === 0 ||
        window.outerHeight === 0 ||
        !navigator.permissions
      );
    };

    const suspectLanguages = () => data.languages.length === 0 || data.languages.some(lang => !lang);
    const unusualScreen = () => data.screen.width <= 1 || data.screen.height <= 1;
    const webGLAnomaly = () => !isWebGLVerified(data);
    const browserEngineMismatch = () => !isBrowserEngineValid(data);
    const checkCookies = () => !data.cookieEnabled;
    const checkRTC = () => data.rtt !== null && (data.rtt <= 0 || data.rtt > 2000);
    const isChromeDevTools = () => window.chrome !== undefined;
    const isMobile = () => isMobileUserAgent(data.userAgent, data.touchPoints, data.screen);

    if (suspectLanguages()) detection.anomalies.push('Suspect language configuration');
    if (webGLAnomaly()) detection.anomalies.push('WebGL anomaly detected');
    if (browserEngineMismatch()) detection.anomalies.push('Browser-Engine mismatch detected');
    if (checkCookies()) detection.anomalies.push('Cookies are disabled');
    if (checkRTC()) detection.anomalies.push('Unusual RTT detected');
    if (isChromeDevTools()) detection.anomalies.push('Chrome DevTools detected');
    
    if (isHeadless()) {
      detection.isBot = true;
      detection.detectedBotKind = 'headless';
      detection.anomalies.push('Headless browser detected');
    }
    if (unusualScreen()) {
      detection.isBot = true;
      detection.detectedBotKind = 'unusual_screen';
      detection.anomalies.push('Unusual screen size detected');
    }
    const suspiciousUAResult = await suspiciousUA(data.userAgent);
    if (suspiciousUAResult && suspiciousUAResult !== false) {
      detection.isBot = true;
      detection.detectedBotKind = suspiciousUAResult;
      detection.anomalies.push('Suspicious User-Agent detected');
    }

    // Add mobile detection to data
    data.isMobile = isMobile() ? 'true' : 'false';

    detection.anomaliesCount = detection.anomalies.length;
    // Enforce bot detection based on anomalies count
    if (detection.anomaliesCount >= config.anomaliesCountLimit) {
      detection.isBot = true;
    }

    return detection;
  };

  const displayBotDetectionResults = async () => {
    try {
      const data = collectData();
      const detectionResult = await detectBot(data);

      const result = config.enableClientDataCollection ? 
        { browserComponents: data, detectionResult: detectionResult } : 
        { detectionResult: detectionResult };

      return result;
    } catch (error) {
      throw error; // Re-throw the error.
    }
  };

  // --- browser detection logic (END) ---

  // Utility functions
  async function checkNetworkStatus() {
    return navigator.onLine;
  }

  function verifyConfig() {
    let errorMessage = '';
    if (typeof config.serverUrl !== 'string' || config.serverUrl.trim() === '') {
      errorMessage = 'Invalid server URL. Please check your configuration.';
    }
    if (typeof config.endPoint !== 'string' || config.endPoint.trim() === '') {
      errorMessage = 'Invalid end-point. Please check your configuration.';
    }
    if (errorMessage) {
      console.error(errorMessage);
      return false;
    }
    return true;
  }

  // Final redirect when successfully passed
  function redirectToSuccessPage() {
    if (document.querySelector('.spinner-small')) document.querySelector('.spinner-small').style.opacity = '0';

    // Redirect
    let url;
    url = new URL(config.endPoint, window.location.href);
    if (url && url.origin === window.location.origin) {
      window.location.replace(url);
      return;
    } else {
      console.error('Invalid end-point. Please check your configuration.');
      return;
    }
  }

  // --- Main script Logic (START) ---
  async function initApp() {
    if (!checkNetworkStatus()) {
      errorLog('No network connection.');
      return;
    }

    if (!verifyConfig()) return;
    if (config.showLoadingScreen) loadLoadingScreen();

    try {
      const resultClient = await displayBotDetectionResults();
      if (resultClient) {
        // Not required to send this data to the server
        delete resultClient.detectionResult["anomalies"];

        if (config.enableClientDataCollection && window.location.protocol === 'https:') { // Only send client data if the page is loaded over HTTPS
          sendClientInfoGetCredentals(resultClient);
        } else {
          delete resultClient.browserComponents;
          sendClientInfoGetCredentals(resultClient);
        }
      } else {
        sendClientInfoGetCredentals({ collectDataFailed: true });
      }
    } catch (error) {
      errorLog("Error:", error);
    }
  }

  async function sendClientInfoGetCredentals(data = {}) {
    try {
      if (!checkNetworkStatus()) {
        throw new Error('No network connection.');
      }

      let jsBotDetected = false;
      if (data.detectionResult && data.detectionResult.isBot === true) {
        jsBotDetected = true;
      }

      // Data collection failed
      if (config.enableClientDataCollection && data.collectDataFailed) {
        jsBotDetected = true;
      }

      data.nonice = generateNonce();

      const response = await fetch(config.serverUrl, {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Referrer-Policy': 'strict-origin'
        },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        throw new Error('An error occurred while processing your request.');
      }

      const result = await response.json();
      
      if (!result) {
        throw new Error('Invalid server response');
      }

      if (config.debug && result.error) throw new Error(result.error.message);

      if (result.reload === true) {
        retryConnection(false);
        return;
      }

      csrfToken = result.csrfToken || '';
      challenge = result.challenge || '';
      difficulty = Number(result.difficulty) || difficulty;
      threshold = Number(result.threshold) || threshold;

      fastInitiateConnection(jsBotDetected);

    } catch (error) {
      errorLog('Request failed:', error);
      errorStopLoadingScreen();
    }
  }

  async function fastInitiateConnection(jsBotDetected = false) {
    try {
      if (!checkNetworkStatus()) {
        throw new Error('No network connection.');
      }

      if (!csrfToken || typeof csrfToken !== 'string') {
        retryConnection(true);
        throw new Error('Token not found');
      }

      const vgText = document.querySelector('.vg-text');
      if (vgText) vgText.textContent = 'Validating...';

      hasUserInteracted();  // Check if user has interacted

      if (!challenge || typeof challenge !== 'string') {
        throw new Error('Missing or invalid challenge');
      }

      const nonce = await solvePoW(challenge);

      const submitResponse = await fetch(config.serverUrl, {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${csrfToken}`,
          'Accept': 'application/json',
          'Referrer-Policy': 'strict-origin'
        },
        body: JSON.stringify({ nonce })
      });

      if (!submitResponse.ok) {
        throw new Error('An error occurred while processing your request.');
      }

      const result = await submitResponse.json();

      if (!result) {
        throw new Error('Invalid server response');
      }

      if (config.debug && result.error) console.error(result.error.message);

      if (result.reload === true) {
        retryConnection(true);
        return;
      }

      if (result.success === true) {
        if (config.showLoadingScreen) {
          if (difficulty >= threshold || jsBotDetected === true) {
            addCheckboxForm().catch(error => {
              errorLog(error);
              errorStopLoadingScreen();
            }).then(checkboxFormAdded => {
              if (checkboxFormAdded === true) {
                redirectToSuccessPage();
              }
            });
          } else {
            if (vgText) vgText.textContent = 'Done!';  // Validated
            redirectToSuccessPage();
          }
        } else {
          if (difficulty >= threshold || jsBotDetected === true) {
            // what to do when UI is not enabled but bot detected?
            // for now, just redirect to success.
            redirectToSuccessPage();
          } else {
            redirectToSuccessPage();
          }
        }
      } else {
        retryConnection(false);
        throw new Error('Request failed.');
      }
    } catch (error) {
      errorLog(error);
      errorStopLoadingScreen();
    }
  }

  function addCheckboxForm() {
    return new Promise((resolve, reject) => {
      const checkbox = document.getElementById('vg-checkbox');
      const spinner = document.querySelector('.spinner-small');
      const vgText = document.querySelector('.vg-text');

      if (spinner) {
        spinner.remove();
      }

      if (checkbox) {
        checkbox.checked = false;
        checkbox.disabled = false;
        checkbox.style.display = 'flex';
        vgText.textContent = 'Click to proceed';

        checkbox.addEventListener('change', async () => {
          if (checkbox.checked) {
            checkbox.disabled = true;
            try {
              const success = await sendCheckboxForm(csrfToken);
              if (success) {
                resolve(true);
              } else {
                reject(new Error('Checkbox form submission invalid.'));
              }
            } catch (error) {
              errorLog('Error in sendCheckboxForm:', error);
              reject(error);
            }
          }
        });
      } else {
        reject(new Error('Checkbox not found.'));
      }
    });
  }

  // Function to handle the server request
  async function sendCheckboxForm(csrfToken) {
    try {
      if (!checkNetworkStatus()) {
        throw new Error('No network connection.');
      }

      if (!csrfToken || typeof csrfToken !== 'string') {
        retryConnection(true);
        throw new Error('Token not found');
      }

      const interacted = hasUserInteracted();

      const response = await fetch(config.serverUrl, {
        method: 'POST',
        mode: 'cors',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${csrfToken}`,
          'Accept': 'application/json',
          'Referrer-Policy': 'strict-origin'
        },
        body: JSON.stringify({
          checkboxClicked: true,
          interacted: interacted
        })
      });

      if (!response.ok) {
        throw new Error('An error occurred while processing your request.');
      }

      const result = await response.json();

      if (!result) {
        throw new Error('Invalid server response');
      }

      if (config.debug && result.error) console.error(result.error.message);

      if (result.reload === true) {
        retryConnection(true);
        return false;
      }

      if (result.success === true) {
        return true; // Resolve when server confirms success
      } else {
        retryConnection(false);
        throw new Error('Request failed.');
      }
    } catch (error) {
      errorLog('Error in sendCheckboxForm:', error);
      throw error;
    }
  }

  // --- Main script Logic (END) ---

  function generateNonce() {
    const nonceFc = Array.from(crypto.getRandomValues(new Uint8Array(10))).map(x => x.toString(16).padStart(2, '0')).join('');
    return nonceFc;
  }
  
  function retryConnection(clearCsrf = false) {
    if (clearCsrf === true) {
      csrfToken = '';
      challenge = '';
    }
    const hasRunRetry = sessionStorage.getItem('hasRunRetry') ? true : false;
    
    if (hasRunRetry !== 'true') {
      sessionStorage.setItem('hasRunRetry', 'true');
      location.reload(true);
    }
  }

  function errorStopLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
      const vgText = document.querySelector('.vg-text');
      const spinner = document.querySelector('.spinner-small');
      const checkbox = document.getElementById('vg-checkbox');

      if (checkbox) checkbox.style.display = 'none';
      if (spinner) spinner.remove();
      if (vgText) vgText.textContent = 'A error occurred.';

      clearLoadingScreen();
    }
  }

  function clearLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
      loadingScreen.remove();
    }
  }

  // Function to load the HTML loading screen
  function loadLoadingScreen() {
    const loadingScreenHtml = `
      <div class="loading-screen" id="loading-screen" role="alert" aria-live="assertive">
        <div class="vg-container">
          <div class="section-one">
            <div class="spinner-small" role="status" aria-label="Loading indicator"></div>
            <input type="checkbox" id="vg-checkbox" name="vg-checkbox" class="captcha-checkbox" aria-labelledby="vg-text" disabled>
          </div>
          <div class="section-two">
            <span class="vg-text" id="vg-text" aria-hidden="true">Loading...</span>
            <noscript class="vg-text noscript">Please enable JavaScript to continue.</noscript>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', loadingScreenHtml);
  }

  function hasUserInteracted() {
    if (userInteracted) return true;

    const onInteraction = () => {
      userInteracted = true;
      document.removeEventListener('mousemove', onInteraction);
      document.removeEventListener('scroll', onInteraction);
      document.removeEventListener('keydown', onInteraction);
      document.removeEventListener('touchstart', onInteraction);
    };  
    document.addEventListener('mousemove', onInteraction);
    document.addEventListener('scroll', onInteraction);
    document.addEventListener('keydown', onInteraction);
    document.addEventListener('touchstart', onInteraction);

    return userInteracted;
  }

  async function solvePoW(challenge) {
    let nonce = 0;
    const target = '0'.repeat(difficulty);

    while (true) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challenge + nonce));
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

      if (hashHex.startsWith(target)) {
        return nonce.toString();
      }
      nonce++;
    }
  }

  // --- Public Initialization Function ---
  window.initDosProtection = (userConfig = {}) => {
    Object.assign(config, userConfig);  // Merge user-provided configuration with defaults
    window.addEventListener('load', initApp);
  };

  window.initDosProtection(); // Default initialization, unless custom config is included
  
  /* For setting custom start vars.
  window.initDosProtection({
    serverUrl: './server.php',
    endPoint: '/home',
    debug: true,
  });*/
})();