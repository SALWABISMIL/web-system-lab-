

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import socket
import ipaddress
import time
from urllib.parse import urlparse

app = Flask(__name__)

# Allow requests from your GitHub Pages dashboard.
# Restrict this to your actual Pages origin once deployed.
CORS(app)

TIMEOUT = 12
MAX_BODY = 20000


def validate_target(raw_url):
    raw_url = (raw_url or "").strip()

    if not raw_url:
        raise ValueError("Please provide a URL.")

    if any(ord(ch) < 32 for ch in raw_url):
        raise ValueError("Invalid characters in URL.")

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported.")

    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid URL.")

    hostname = parsed.hostname.lower()

    # Reject local names and private IP addresses to reduce SSRF risk.
    if hostname in ("localhost",) or hostname.endswith(".localhost"):
        raise ValueError("Localhost targets are not allowed.")

    try:
        ip = ipaddress.ip_address(hostname)
        if not ip.is_global:
            raise ValueError("Private or non-public IP addresses are not allowed.")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
        # A non-IP hostname is allowed; DNS is resolved by requests.

    return raw_url


@app.get("/")
def home():
    return jsonify({
        "service": "Web System Lab API",
        "status": "online",
        "endpoints": ["/api/health", "/api/test"]
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "online"})


@app.get("/api/test")
def test_url():
    raw_url = request.args.get("url", "")

    try:
        url = validate_target(raw_url)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    started = time.time()

    try:
        with requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "WebSystemLab/1.0"}
        ) as response:
            elapsed = round((time.time() - started) * 1000)

            headers = dict(response.headers)
            body = ""

            # Read only a bounded amount of the response.
            content_type = response.headers.get("Content-Type", "")
            if "text" in content_type or "json" in content_type or "xml" in content_type:
                chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=4096):
                    if not chunk:
                        continue
                    remaining = MAX_BODY - size
                    chunks.append(chunk[:remaining])
                    size += min(len(chunk), remaining)
                    if size >= MAX_BODY:
                        break
                body = b"".join(chunks).decode("utf-8", errors="replace")

            return jsonify({
                "success": True,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "reason": response.reason,
                "elapsed_ms": elapsed,
                "headers": headers,
                "body": body,
                "body_truncated": len(body) >= MAX_BODY
            })

    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "url": url,
            "error": "The target did not respond before the timeout."
        }), 504

    except requests.exceptions.RequestException as exc:
        return jsonify({
            "success": False,
            "url": url,
            "error": "The request failed.",
            "detail": str(exc)[:500]
        }), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
