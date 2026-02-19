import re
import json
import sys
import os

# Add parent dir so we can import jsmon
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsmon

# ===== Test Content: simulates real-world JS patterns =====
test_content = """
    // --- Full URLs ---
    var api = "https://api.example.com/v1/user";
    var cdn = "//cdn.example.net/lib.js";
    var ftp = "ftp://files.example.com/data";
    var ws  = "wss://realtime.example.com/socket";
    var ssh = "ssh://git@github.com:user/repo.git";
    var smb = "smb://192.168.1.10/share";

    // --- Relative paths ---
    var relative = "/api/v2/config";
    var dot_relative = "./js/app.js";
    var parent_relative = "../assets/img.png";
    var rest_api = "/api/v1/services/status";
    var file_path = "config.json?debug=true";
    var action_path = "login.action#auth";

    // --- HTTP Method calls ---
    axios.get('/api/users');
    router.post('/login');
    app.put('/api/v1/config');
    request.delete('/resource/123');
    http.patch('/profile/update');

    // --- fetch() calls ---
    fetch('/api/data');
    fetch("https://api.example.com/v2/items");

    // --- axios extended ---
    axios.post('/api/submit');
    axios({ url: '/api/batch' });

    // --- jQuery AJAX ---
    $.ajax({ url: '/api/jquery/data' });
    $.get('/api/jquery/list');
    $.post('/api/jquery/create');
    $.getJSON('/api/jquery/json');

    // --- XMLHttpRequest ---
    xhr.open('GET', '/api/xhr/resource');

    // --- WebSocket ---
    var socket = new WebSocket('wss://ws.example.com/live');

    // --- src/href attributes ---
    <script src="/static/bundle.js"></script>
    <link href="/css/style.css">
    <img src="https://img.example.com/logo.png">

    // --- window.location ---
    window.location.href = '/dashboard/home';

    // --- Template literals (backticks) ---
    var url = `https://api.example.com/v3/search`;
    var ep = `/api/v4/results`;

    // --- GraphQL ---
    var gql = "/graphql";

    // --- API Keys ---
    var googleKey = "AIzaSyC_0123456789abcdefghijklmnopqrstu";
    var awsKey = "AKIAIOSFODNN7EXAMPLE";
    var stripeKey = "sk_live_abcdefghijklmnopqrstuvwx";
    var sendgridKey = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq";
    var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123def456ghi";
    var ghToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

    // --- IP and Email ---
    var server = "192.168.1.100";
    var mail = "admin@example.com";

    // --- False positives that should NOT appear ---
    var mime = "application/json";
    var css = "100px";
    var color = "#ffffff";
    var dataUri = "data:image/png";
"""

print("=" * 60)
print("JSMon Pattern Matching Test Suite")
print("=" * 60)

findings = jsmon.scan_for_secrets(test_content)
print("\nFindings:")
print(json.dumps(findings, indent=2, sort_keys=True))

# ===== Expected Results =====
expected = {
    "URLs": [
        "https://api.example.com/v1/user",
        "//cdn.example.net/lib.js",
        "ftp://files.example.com/data",
        "wss://realtime.example.com/socket",
        "wss://ws.example.com/live",
        "https://api.example.com/v2/items",
        "https://api.example.com/v3/search",
        "https://img.example.com/logo.png",
    ],
    "Domains": [
        "api.example.com",
        "cdn.example.net",
        "files.example.com",
        "realtime.example.com",
        "ws.example.com",
        "img.example.com",
    ],
    "Endpoints": [
        "/api/v2/config",
        "./js/app.js",
        "../assets/img.png",
        "/api/v1/services/status",
        "config.json?debug=true",
        "login.action#auth",
        "/api/users",
        "/login",
        "/api/v1/config",
        "/resource/123",
        "/profile/update",
        "/api/data",
        "/api/submit",
        "/api/batch",
        "/api/jquery/data",
        "/api/jquery/list",
        "/api/jquery/create",
        "/api/jquery/json",
        "/api/xhr/resource",
        "/static/bundle.js",
        "/css/style.css",
        "/dashboard/home",
        "/api/v4/results",
        "/graphql",
    ],
    "Google API Key": ["AIzaSyC_0123456789abcdefghijklmnopqrstu"],
    "AWS API Key": ["AKIAIOSFODNN7EXAMPLE"],
    "Stripe Secret Key": ["sk_live_abcdefghijklmnopqrstuvwx"],
    "Email": ["admin@example.com"],
    "IP Address": ["192.168.1.100"],
}

# ===== Validation =====
print("\n" + "=" * 60)
print("Validation Results")
print("=" * 60)

failures = []
passes = 0

for category, expected_items in expected.items():
    found = findings.get(category, [])
    missing = [e for e in expected_items if e not in found]
    if missing:
        failures.append(f"  MISSING in [{category}]: {missing}")
    else:
        passes += 1

# Check false positives are NOT present
false_positive_checks = ["application/json", "100px", "#ffffff", "data:image/png"]
fp_found = []
all_values = []
for v in findings.values():
    if isinstance(v, list):
        all_values.extend(v)
for fp in false_positive_checks:
    if fp in all_values:
        fp_found.append(fp)

if fp_found:
    failures.append(f"  FALSE POSITIVES detected: {fp_found}")

total = len(expected) + 1  # +1 for false positive check
if not fp_found:
    passes += 1

print(f"\nPassed: {passes}/{total}")
if failures:
    print("FAILED:")
    for f in failures:
        print(f)
    sys.exit(1)
else:
    print("SUCCESS: All expected results found, no false positives.")
