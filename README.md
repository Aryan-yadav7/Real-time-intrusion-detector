# Real-Time Web Intrusion Detection System (IDS)

## 1. Project Overview

The Real-Time Web Intrusion Detection System (IDS) is a security platform designed to protect websites from cyberattacks.

It monitors incoming HTTP requests, detects suspicious activities, and blocks malicious requests in real time. It also provides a live dashboard where website owners can monitor security events and understand potential threats.

The platform supports multiple users, allowing each user to register their own websites, integrate the security SDK and monitor their websites through individual dashboards.

### Key Features

- Real-time detection of malicious HTTP requests.
- Detection of SQL Injection, XSS, NoSQL Injection, Path Traversal and other attacks.
- Behaviour-based detection of brute force, flooding and suspicious scanning.
- Threat scoring between 0 and 100.
- Detect-only and blocking modes.
- Live security dashboard with real-time updates.
- User registration and authentication.
- Multiple website registration under different user accounts.
- Unique API keys for individual websites.
- Python SDK for integrating protection into customer websites.
- Secure event ingestion through an API.
- Separate dashboards and data for each website owner.
- Secure storage and privacy-focused event handling.

## 2. Types of Attacks Detected

The IDS detects two main categories of attacks.

### A. Payload-Based Attacks

These attacks are identified by inspecting individual HTTP requests.

| Attack | Description |
|---|---|
| SQL Injection | Attempts to manipulate database queries using malicious SQL input. |
| NoSQL Injection | Attempts to manipulate NoSQL database queries. |
| XSS (Cross-Site Scripting) | Attempts to inject malicious JavaScript into a website. |
| Path Traversal | Attempts to access restricted files and directories. |
| Command Injection | Attempts to execute system commands through an application. |
| PHP/Code Injection | Attempts to inject malicious code into an application. |
| Template Injection | Attempts to execute malicious template expressions. |
| Log4Shell | Detects attempts to exploit vulnerable logging systems through JNDI expressions. |
| CRLF Injection | Attempts to manipulate HTTP headers. |
| Scanner Detection | Detects automated tools scanning websites for vulnerabilities. |
| Sensitive File Probing | Detects attempts to access files such as `.env`, `.git` and admin panels. |

### B. Behaviour-Based Attacks

These attacks are detected by monitoring patterns of activity over time.

| Attack | Description |
|---|---|
| Flood Attack | Detects too many requests coming from a single IP address within a short period. |
| Brute Force | Detects repeated attempts to guess login credentials. |
| Credential Stuffing | Detects login attempts involving multiple usernames and credentials. |
| Scanning | Detects repeated requests for missing pages and directories. |

## 3. System Architecture

The system consists of two main parts:

1. **Customer Website:** The website where the IDS SDK is installed and attacks are detected locally.
2. **Guard Platform:** The central server that manages users, websites, API keys, security events and dashboards.

### Architecture Diagram

```text
                 CUSTOMER'S WEBSITE
                  (Customer Server)
                         |
                         v
                  GuardMiddleware
                         |
             +-----------+-----------+
             |                       |
             v                       v
        rules.py                behavior.py
      Payload Detection      Behaviour Detection
             |                       |
             +-----------+-----------+
                         |
                         v
                  Threat Analysis
                         |
                 Detect / Block
                         |
                         v
                     LocalSink
                         |
                         or
                         |
                     RemoteSink
                         |
                  Queue + Thread
                         |
                Sends events every 2 sec
                         |
                         v
                  GUARD PLATFORM
                    Port 9000
                         |
                         v
                  POST /api/v1/events
                         |
                  API Key Validation
                         |
                    Rate Limiting
                         |
                         v
                  Platform Database
                       SQLite
                         |
             +-----------+-----------+
             |                       |
             v                       v
         User Account 1          User Account 2
             |                       |
             v                       v
        Website Dashboard      Website Dashboard
```

### How the System Works

1. A visitor sends an HTTP request to a customer's website.
2. GuardMiddleware intercepts the request.
3. The rules engine checks the request for malicious payloads.
4. The behaviour engine checks for suspicious activity from the IP address.
5. The system calculates a threat score and identifies potential attacks.
6. Depending on the configured mode, the request is allowed or blocked.
7. Security events are stored locally or sent to the central Guard platform.
8. The platform validates the website's API key and stores the received events.
9. The website owner can view security events through their personal dashboard.

**Important:** Detection and blocking happen locally inside the customer's application. Therefore, the customer's website can continue receiving protection even if the central Guard platform is unavailable.

## 4. Project Files and Their Responsibilities

### A. Core Detection and Middleware

| File | Description |
|---|---|
| `ids/rules.py` | Contains the rule engine for detecting payload-based attacks. It normalizes certain encoded and obfuscated inputs before matching them against detection rules. |
| `ids/behavior.py` | Tracks IP addresses using sliding time windows and detects flooding, brute force, credential stuffing and scanning behaviour. |
| `ids/middleware.py` | Intercepts incoming HTTP requests, runs detection engines and handles allowing or blocking requests. |
| `ids/messages.py` | Provides plain-language threat explanations, headlines and recommendations. |
| `ids/status.py` | Determines the security status displayed on the dashboard using recent events. |

### B. Database and Event Storage

| File | Description |
|---|---|
| `ids/db.py` | Stores requests and detected security events in SQLite. |
| `ids/platform_db.py` | Stores user accounts, sessions and registered websites for the Guard platform. |
| `ids/sinks.py` | Provides LocalSink and RemoteSink for handling and forwarding security events. |

### C. Platform and Authentication

| File | Description |
|---|---|
| `ids/auth.py` | Handles password hashing, authentication tokens, sessions and API keys. |
| `ids/ratelimit.py` | Implements rate limiting to protect the platform from excessive requests and abuse. |
| `ids/platform_app.py` | Main application for the central Guard platform, including registration, website management and event ingestion. |
| `ids/static/app.html` | Frontend for account registration, login and website management. |

### D. Dashboard and SDK

| File | Description |
|---|---|
| `ids/dashboard.py` | Provides dashboard APIs, snapshots and Server-Sent Events for live updates. |
| `ids/static/dashboard.html` | Frontend for displaying security status, attack information and recent events. |
| `ids/sdk.py` | Provides GuardMiddleware for integrating the IDS into customer Python/ASGI applications. |
| `ids/customer_demo.py` | Demonstrates a customer website protected using the Guard SDK. |
| `ids/demo_app.py` | Provides a sample website with the original IDS dashboard mounted at `/ids/`. |

### E. Testing

| File | Description |
|---|---|
| `tests/test_rules.py` | Tests attack detection rules using malicious and harmless inputs. |
| `tests/test_auth.py` | Tests authentication, password hashing and API key functionality. |
| `tests/test_platform.py` | Tests platform functionality, website management and user isolation. |
| `tests/test_sdk.py` | Tests SDK integration and middleware behaviour. |

### F. Attack Simulation

| File | Description |
|---|---|
| `scripts/attack.py` | Generates simulated malicious requests to test the detection and blocking capabilities of the IDS. |

## 5. Main Components Explained

### 5.1 Middleware

Middleware acts as a security checkpoint between the client and the website.

Whenever an HTTP request arrives, the middleware:

- Intercepts the request.
- Sends request information to the rules engine.
- Checks suspicious behaviour using the behaviour engine.
- Calculates the threat score.
- Decides whether the request should be allowed or blocked.
- Sends detected security events to the configured sink.

The system supports two operating modes:

| Mode | Description |
|---|---|
| Detect Mode | Detects and records attacks without blocking requests. |
| Block Mode | Detects attacks and blocks dangerous requests. |

In block mode:

- HTTP `403 Forbidden` is returned for dangerous payloads.
- HTTP `429 Too Many Requests` is returned for IP addresses with active behaviour alerts.

The middleware also follows a fail-open approach. This means an IDS error should not bring down the protected website.

### 5.2 Rules Engine

The rules engine is responsible for detecting malicious request payloads.

It examines:

- URL paths.
- Query parameters.
- Request bodies.
- HTTP headers.

It also handles certain obfuscated inputs before checking them against the rules.

For example, attackers may use URL encoding, SQL comments or obfuscated Log4Shell expressions to bypass basic detection. The rules engine attempts to normalize these inputs before matching them.

### 5.3 Behaviour Detection Engine

The behaviour engine monitors how frequently an IP address sends requests.

It uses sliding time windows to identify suspicious patterns.

Examples:

- Too many requests within a short period may indicate a flood attack.
- Repeated failed login attempts may indicate brute force.
- Requests for multiple missing pages may indicate scanning.

Alerts remain active during a cooldown period of 2 minutes to avoid generating thousands of duplicate alerts.

### 5.4 Threat Scoring

The system calculates a threat score between 0 and 100 based on detected suspicious activity.

This score helps communicate the severity of a request or security event.

### 5.5 Database

The project uses SQLite for storing security information.

There are two main database components:

- `db.py`: Stores request information and security events for the original IDS.
- `platform_db.py`: Stores user accounts, sessions and registered websites for the multi-user platform.

### 5.6 Dashboard

The project provides two dashboard interfaces.

**IDS Dashboard**

- Displays detected attacks.
- Shows the current security status.
- Displays recent security events.
- Updates automatically using Server-Sent Events (SSE).

**Guard Platform Dashboard**

- Allows users to register and log in.
- Allows users to add and manage websites.
- Generates unique API keys for websites.
- Displays website-specific security events.
- Provides separate dashboards for different website owners.

### 5.7 SDK and Event Sinks

The Python SDK allows customers to integrate the IDS into their own websites.

`ids/sdk.py` provides GuardMiddleware.

`ids/sinks.py` provides two event storage and delivery options:

| Sink | Description |
|---|---|
| LocalSink | Stores security events locally using the original IDS storage mechanism. |
| RemoteSink | Sends security events to the central Guard platform using a background queue and thread. |

The middleware uses a sink object instead of directly accessing the database. This makes the system flexible and allows the same detection engine to work with different storage destinations.

## 6. Multi-User Platform and Event Ingestion

The Guard platform allows multiple customers to protect their websites independently.

### User Registration and Website Management

1. A customer creates an account on the Guard platform.
2. The customer logs in.
3. The customer adds a website.
4. The platform generates a unique API key for that website.
5. The customer configures the SDK using the API key.

### Event Ingestion API

The central platform receives security events through:

```http
POST /api/v1/events
```

The API key identifies the website associated with the incoming events.

The platform then:

1. Validates the API key.
2. Applies rate limiting.
3. Validates the incoming event payload.
4. Stores the events in the platform database.
5. Makes the events available on the website owner's dashboard.

The platform rejects a `site_id` supplied in the event payload because the API key itself determines which website receives the events.

### Privacy and Data Handling

Only limited security metadata is sent to the central platform:

- Request path (without query string).
- Short, redacted evidence snippet.
- IP address.
- User-Agent.

The following information is never sent:

- Passwords.
- Cookies.
- Usernames.
- Complete request bodies.

## 7. Security Features

Security is an important part of the platform.

| Security Feature | Implementation | Purpose |
|---|---|---|
| Password Security | Salted scrypt hashing | Prevents passwords from being stored in plain text. |
| API Key Security | Random 256-bit API keys | Provides secure authentication for customer websites. |
| Token Storage | SHA-256 hashes | Prevents stored tokens and API keys from being directly reused if the database is stolen. |
| Session Security | HttpOnly and SameSite=Lax cookies | Protects user sessions from common browser-based attacks. |
| Secure Cookies | Secure flag over HTTPS | Ensures cookies are transmitted securely. |
| CSRF Protection | CSRF tokens | Prevents unauthorized state-changing requests through another website. |
| Tenant Isolation | Website ID and owner ID validation | Prevents users from accessing other users' data. |
| Rate Limiting | Limits login, registration and ingestion requests | Protects against brute force and abuse. |
| Payload Validation | Schema checks, length limits and size restrictions | Prevents invalid or oversized event data. |
| XSS Protection | Content Security Policy and safe text rendering | Protects dashboards from malicious scripts. |
| Data Retention | Deletes events older than 30 days | Reduces unnecessary data storage. |

Additional security measures:

- API keys are shown only once when generated.
- Login errors use similar messages for nonexistent accounts and incorrect passwords.
- Live connections are limited to five per user.
- Live streams end when the associated session ends.
- Deleting a website also deletes its associated security data.
- Event batches are limited to 200 items.
- Ingestion payloads have a 1 MB size limit.
- Timestamps are clamped and control characters are stripped.

## 8. Installation and Setup

The following instructions are for Windows 11 using PowerShell.

### Step 1: Clone or Open the Project

```powershell
cd ids-project
```

### Step 2: Create a Virtual Environment

```powershell
py -m venv .venv
```

### Step 3: Activate the Virtual Environment

```powershell
.venv\Scripts\Activate.ps1
```

### Step 4: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 5: Run Tests

```powershell
python -m pytest -q
```

## 9. Running the Project

There are two ways to run and test the system.

### A. Run the Original IDS Demo

Open a PowerShell terminal and execute:

```powershell
python -m uvicorn ids.demo_app:app --port 8000
```

Open the dashboard in your browser:

http://127.0.0.1:8000/ids/

Open another PowerShell terminal and execute:

```powershell
python scripts\attack.py --everything
```

The attack script generates different simulated attacks.

You can watch the dashboard display the detected events in real time.

### Enable Blocking Mode

To enable blocking mode, execute:

```powershell
$env:IDS_MODE = "block"

python -m uvicorn ids.demo_app:app --port 8000
```

In blocking mode, dangerous requests are rejected.

**Note:** The attack script's own IP may get blocked for 2 minutes after the brute-force simulation. Later attack tests may return HTTP `429`. This is expected behaviour when blocking is working.

### B. Run the Multi-User Guard Platform

The platform requires three separate PowerShell terminals.

**Terminal 1: Start the Guard Platform**

```powershell
python -m uvicorn ids.platform_app:create_app --factory --port 9000
```

Open the platform:

http://127.0.0.1:9000

Create an account, log in, click **Add Website** and copy the generated API key.

**Terminal 2: Start the Customer Website**

Set the API key generated by the platform:

```powershell
$env:GUARD_API_KEY = "gk_...paste-your-key..."
```

Start the customer demo application:

```powershell
python -m uvicorn ids.customer_demo:app --port 8000
```

**Terminal 3: Simulate Attacks**

```powershell
python scripts\attack.py --everything
```

Open the Guard platform and click **Open Dashboard** for the registered website.

You should see the security events appearing on the website's dashboard.

### Test Multi-User Isolation

To verify that user data is separated:

1. Create an account in your normal browser.
2. Register a website and generate an API key.
3. Open the platform in a private/incognito browser window.
4. Create another account.
5. Verify that the second account cannot access the first account's website or security events.

## 10. Configurable Settings

The system provides environment variables and configuration options to control its behaviour.

| Setting | Description |
|---|---|
| `IDS_MODE` | Controls the original IDS detection or blocking mode. |
| `GUARD_DB` | Sets the Guard platform database file. Default: `guard.db`. |
| `GUARD_API_KEY` | Stores the customer's website API key. |
| `GUARD_MODE` | Controls the customer SDK detection or blocking mode. |
| `GUARD_SERVER` | Sets the address of the central Guard platform. |
| `GUARD_COOKIE_SECURE` | Enables secure session cookies when using HTTPS. |

Additional behaviour detection settings, such as thresholds and time windows, can be modified through `BehaviorConfig` in `ids/behavior.py`.

The middleware also supports configurable `mode` and `block_threshold` settings.

## 11. Known Limitations

The project currently has some limitations that can be improved in future versions.

1. **Regex-Based Detection:** Sophisticated attackers may bypass some detection rules using advanced obfuscation techniques.
2. **Process-Based Behaviour Tracking:** Behaviour counters are stored in RAM and are maintained separately by each Python process.
3. **IP-Based Blocking:** Users sharing the same public IP address may be blocked together.
4. **Request Body Inspection:** Request bodies larger than 1 MB are not inspected.
5. **Distributed DDoS Protection:** Large-scale attacks involving thousands of IP addresses require network-level protection.
6. **Multiple Workers:** Rate-limit counters and session caches are currently per process. Redis would be required for shared state across multiple workers.
7. **Account Recovery:** Email verification and password reset are not implemented yet.
8. **HTTPS Requirement:** API keys must be transmitted over HTTPS in real deployments.
9. **Database Scalability:** SQLite is suitable for this project, but PostgreSQL would be more appropriate for a large production platform.
10. **SDK Support:** The current SDK supports Python/ASGI applications. Node.js SDK support is planned.
11. **Additional Platform Features:** Team management, roles, billing and domain ownership verification are not implemented.

## 12. Future Enhancements

The following features are planned for future development:

- Email, Telegram and SMS security alerts.
- Per-website alert configuration.
- AI-based attack explanations.
- AI security assistant or chatbot.
- Machine learning-based attack classification.
- Node.js SDK for JavaScript applications.
- Security summaries and reports.
- Additional detection rules for SSRF, XXE and open redirects.
- Better distributed rate limiting using Redis.
- PostgreSQL support for larger deployments.
- Email verification and password recovery.

## 13. Project Summary

The Real-Time Web Intrusion Detection System is a platform that protects websites by monitoring incoming requests and identifying suspicious activities.

It combines payload-based detection, behaviour-based detection, threat scoring, request blocking, event storage and live monitoring.

The Python SDK allows customers to integrate the detection system into their own websites, while the central Guard platform manages user accounts, website registration, API keys and individual security dashboards.

**In simple words:** The system works like a security guard for websites. It watches incoming requests, identifies suspicious activities, blocks dangerous requests when enabled, records security events and allows website owners to monitor their website security through a dashboard.

The main goal is to provide an easy-to-use, real-time website security platform that can protect multiple websites independently.