# Aero-sentry
A lightweight javascript bot detection script &amp; Dos protection with server-side PoW challange validation.

## **🔎 Overview**
This repository contains a **JavaScript-based Browser analyze Script** designed to detect and mitigate bot activity and a **Php-based Proof-of-Work (PoW)** challenge and data verification server. 

This system uses a combination of client-side JavaScript and server-side Php to verify that incoming requests are legitimate and not automated, including CSRF protection, bot detection, and a optional rate limiting (`simple-waf.php`).

The solution is lightweight, modular, and configurable, making it suitable for integration into web applications that require enhanced security against automated attacks or suspicious activity.

## **🚀 Features**
1. **Bot Detection (JavaScript)**:
   - Detects headless browsers, suspicious user agents, anomalies and more in clients browser.
   - Uses WebGL, browser engine, and user-agent validation and more to identify bots.

2. **Proof-of-Work (PoW) Challenge**:
   - Implements a PoW mechanism where the client solves a computational challenge before proceeding.
   - Adjustable difficulty levels based on server load or bot detection.

3. **CSRF Protection**:
   - Ensures secure communication with the server using CSRF tokens.

4. **User Interaction Validation**:
   - Tracks basic user interaction to differentiate between bots and real users.

5. **Loading Screen with CAPTCHA checkbox**:
   - Displays a loading screen with a checkbox CAPTCHA for additional user input validation.
  
6. **Rate Limiting & IP filtering (Optional, via simple-WaF)**:
   - Limits the number of requests per IP within a configurable time window.
   - Supports IP blacklisting and whitelisting.
   - Current [blacklist.txt](src/data/ip-blacklist.txt) is fetched from <a href="https://www.projecthoneypot.org" target="_blank">Projecthoneypot.org</a>.

7. **Retry Mechanism**:
   - Implements a retry mechanism for failed requests.

8. **Debugging Tools**:
   - Includes detailed logging for debugging and a js timer for performance analysis.

9. **Low latency**
   - Median latency of <0.6ms (depends on: webserver, configuration, PoW setting, CDN, more..)

## **🏃🏻 Getting Started**

1. Download files:

- [`src/`](src) for **Full** Aero-sentry with **Debugging**, **simple-WaF**, **SQLite3 logging** and full code comments. With `session.php` to show session debugging and current IP.
- [`production/`](production) for Production ready deployment with core Aero-sentry functionality and **SQLite3 logging**.<br>
  Simple-WaF not added by default, recomended to use a better implementation.
- [`js-only/`](js-only) Is for javascript Bot detection only. Without PoW and any Php or server required.

or
- Clone the repository: [https://github.com/280studios/aero-sentry.git](https://github.com/280studios/aero-sentry.git)
- `git clone https://github.com/280studios/aero-sentry.git`

2. Configure:
   - Ensure the server supports PHP and has the required extensions.
   - Update the `config.php` file with your desired settings.
   - Update the config vars in `aero-sentry.js`.

 - <b>IMPORTANT!</b> Both `CLIENT_METADATA_ENABLED` on the server and `enableClientDataCollection` in `aero-sentry.js` must be set to the same value.

3. Include the JavaScript file in your HTML:
   ```html
   <script src="aero-sentry.js"></script>
   ```

4. Initialize the script (Already done in aero-sentry.js by default):
   ```javascript
   window.initDosProtection({
       serverUrl: './server.php',
       debug: true,
   });
   ```

5. Deploy the server-side scripts (`server.php` and `config.php`) to your web server.

6. Move the `data/` directory to the same path as php files.

## **📋 Requirements**

### **Server Requirements**
- **PHP (8.0 or higher recomended, should work for PHP 5+)**
- **Sqlite3** - for ip filtering and rate limit.
- **OpenSSL** - for hash functions
- **APCu** - for caching (else `tmp/` dir is used)
- **Apache or Nginx** - for web server

### **Client Requirements**
- **Modern Browser** (Chrome, Firefox, Edge, etc.)
- **JavaScript** (enabled by default in most browsers)

---

## **🏗️ How It Works**
<p align="center">
  <img src="https://github.com/user-attachments/assets/18652016-3333-419b-a688-e1f1a0f620e2" width="400" height="auto" />
</p>

1. **Initialization**:
   - The script initializes on page load and collects browser metadata.
   - It validates the configuration and displays a loading screen.

2. **Bot Detection**:
   - The client-side script collects browser data and detects any anomalies to detect if the request seems valid.
   - If enabled, the script sends the client data to the server for validation. (You should add a more sophisticated metadata analyzer for better detection)
   - The server evaluates the client data(and PoW) and determines whether the client is a bot.

3. **Proof-of-Work Challenge**:
   - If the client passes initial client validation, a PoW challenge is issued.
   - The client solves the challenge and submits the solution to the server.

4. **CAPTCHA Validation**:
   - If additional validation is required, a checkbox CAPTCHA is displayed.
   - The server validates the CAPTCHA checkbox and grants access upon success.

5. **Server-side metadata collection and analysis**
   - The server receives the client metadata and stores it for analysis (if enabled).
   - You can then use this data to perform further analysis and detect any suspicious activity.

6. **Error Handling**:
   - If any step fails (e.g., invalid CSRF token, expired challenge), the client is instructed to reload the page or retry the request.

---

## **🛠️ Configuration**
The scripts is configurable via the `config` object in the JavaScript file & config.php for the server. Below are the key configuration options:

### **Client-Side Configuration**
| Option                     | Default Value       | Description                                                                 |
|----------------------------|---------------------|-----------------------------------------------------------------------------|
| `serverUrl`                | `'./server.php'`    | URL of the server-side script.                                              |
| `endPoint`                 | `'success.php'`     | URL to redirect to upon successful validation.                              |
| `userAgentsFile`           | `'user-agents.json'`     | List of blocked user-agents and Allowed crawlers.                 |
| `enableClientDataCollection` | `true`            | Whether to collect and send browser metadata to the server.                 |
| `showLoadingScreen`        | `true`              | Whether to display the loading screen during validation.                    |
| `anomaliesCountLimit`      | `3`                 | Number of anomalies required to classify the client as a bot.               |
| `debug`                    | `true`              | Enables detailed logging for debugging purposes.                            |

### **Server-Side Configuration (PoW)**
| Option                     | Default Value       | Description                                                                 |
|----------------------------|---------------------|-----------------------------------------------------------------------------|
| `CHALLENGE_EXPIRY_TIME`    | `300`               | Time (in seconds) before a challenge expires.                               |
| `DEFAULT_DIFFICULTY`       | `3`                 | Default difficulty level for PoW challenges.                                |
| `HIGH_DIFFICULTY`          | `6`                 | Difficulty level for high server load.                                      |
| `BOT_DIFFICULTY`           | `4`                 | Difficulty level for detected bots.                                         |
| `HIGH_LOAD_THRESHOLD`      | `1.0`               | Server load threshold for increasing difficulty, Uses Php: `sys_getloadavg()` |

### **simple-WAF Configuration**
| Option                     | Default Value          | Description                                                              |
|----------------------------|------------------------|--------------------------------------------------------------------------|
| `RATE_LIMIT`               | `30`                   | Maximum number of requests per IP within the rate limit window.          |
| `RATE_LIMIT_WINDOW`        | `10`                   | Time window for rate limiting.                                           |
| `WHITELISTED_IPS`          | `['127.0.0.1']`        | List of IPs exempt from rate limiting and IP filtering.                  |
| `BLACKLISTED_IPS`          |  `'ip-blacklist.txt'`  | List of IPs blocked immediately                                          |

* <b>IMPORTANT!</b>
 - Both `CLIENT_METADATA_ENABLED` on the server and `enableClientDataCollection` in `aero-sentry.js` must be set to the same value.
 - Also the server must use SSL (HTTPS) for the client metadata to be sent to the server.
---

## **🔒 Security Best Practices**
1. **HTTPS**:
   - Ensure the application is served over HTTPS to protect against man-in-the-middle attacks. Client sending of metadata requires SSL.

2. **CSRF Protection**:
   - Use the built-in CSRF token validation to prevent cross-site request forgery.

3. **Rate Limiting**:
   - Configure rate limiting to prevent abuse from a single IP address. (by including `simple-waf.php`)

4. **Challenge Expiry**:
   - Set an appropriate expiry time for challenges to prevent replay attacks.

## **🤝 Contributing**
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

<a href='https://ko-fi.com/X8X11DTGJQ' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi6.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

## **📄 License**
This project is licensed under the GNU General Public License. See the `LICENSE` file for details.

## **📣 Acknowledgments**
Special thanks to the open-source community for providing inspiration for this project.
Inspired by Cloudflare and fingerprintjs/BotD.

