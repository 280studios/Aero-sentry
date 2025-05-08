(function() {  // IIFE for encapsulation
  "use strict";

  // --- Configuration ---
  const config = {
    userAgentsFile: 'user-agents.json',
    showLoadingScreen: true,  // Show the loading screen UI (detection still runs)
    anomaliesCountLimit: 3, // Anomalies limit until the request is blocked
    debug: false,
  };

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

        console.warn('Failed to fetch user-agents.json, using backup.');
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
      console.error('Error loading or processing user-agents.json:', error);
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

      const result = { detectionResult: detectionResult };

      delete result.detectionResult["anomalies"];

      return result;
    } catch (error) {
      throw error;
    }
  };

  async function initApp() {
    try {
      const resultClient = await displayBotDetectionResults();
      if (resultClient) {
        console.log(resultClient.detectionResult);
        console.log("Bot detected: ", resultClient.detectionResult.isBot);
      }
    } catch (error) {
      console.error(error);
    }
  }

  initApp();
})();