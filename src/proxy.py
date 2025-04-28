import asyncio
import hashlib
import hmac
import os
import random
import socket
import sys
import time
import brotli  # Add brotli for content decoding
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

# --- CONFIG ---
SHARED_SECRET = "rXPACddng7mFAbjPP4feLFS1maXg3vpW" # Secret between client & server
version = "1.0.0"                                  # Version of the script
IPV6_PREFIX = "2a01:e5c0:2d74"                     # Your /48 prefix
IPV6_SUBNET = "1000"                               # Using subnet 1000 within your /48
INTERFACE = "ens3"                                 # Detected interface from your system
LISTEN_PORT = 80                                   # Proxy server port
LISTEN_HOST = "0.0.0.0"                            # Listen on all interfaces
REQUEST_TIMEOUT = 30                               # Request timeout in seconds
DEBUG = False                                      # Enable debug output

def random_ipv6():
    """Generate a random IPv6 address within the specified subnet"""
    host = random.getrandbits(64)
    return f"{IPV6_PREFIX}:{IPV6_SUBNET}:{(host >> 48) & 0xFFFF:04x}:{(host >> 32) & 0xFFFF:04x}:{(host >> 16) & 0xFFFF:04x}:{host & 0xFFFF:04x}"

async def check_interface():
    """Check if the configured interface exists"""
    try:
        cmd = "ip link show"
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if INTERFACE not in stdout.decode():
            print(f"WARNING: Interface {INTERFACE} not found in system interfaces.")
            print(f"Available interfaces: {stdout.decode()}")
            return False
        return True
    except Exception as e:
        print(f"Error checking interfaces: {e}")
        return False

async def add_ipv6_to_interface(ipv6):
    """Add IPv6 address to interface if it doesn't exist"""
    if DEBUG:
        print(f"Attempting to add {ipv6}/128 to {INTERFACE}")

    try:
        cmd = f"ip -6 addr add {ipv6}/128 dev {INTERFACE}"
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            stderr_text = stderr.decode()
            if "File exists" not in stderr_text:
                print(f"Failed to add IPv6 address: {stderr_text}")
                return False
            else:
                if DEBUG:
                    print("IPv6 address already exists (this is fine)")
        return True
    except Exception as e:
        print(f"Error adding IPv6 address: {e}")
        return False

async def test_ipv6_connectivity(ipv6):
    """Test if we can use this IPv6 address for outbound connections"""
    if DEBUG:
        print(f"Testing connectivity for {ipv6}")

    try:
        # Create socket with the IPv6 address
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind((ipv6, 0))

        # Try to connect to Google's DNS (doesn't actually send data)
        sock.connect(("2001:4860:4860::8888", 53))
        sock.close()
        if DEBUG:
            print("IPv6 connectivity test PASSED")
        return True
    except Exception as e:
        print(f"IPv6 connectivity test FAILED: {e}")
        return False

def ensure_url_has_scheme(url):
    """Ensure URL has a scheme (http:// or https://)"""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

async def log_request(request):
    """Log detailed information about incoming requests"""
    print("\n--- Incoming Request Details ---")
    print(f"Method: {request.method}")
    print(f"Path: {request.path}")
    print(f"Query string: {request.query_string}")
    print(f"Remote: {request.remote}")
    print(f"Headers: {dict(request.headers)}")
    print("-------------------------------\n")

def derive_dynamic_key():
    """Generate a dynamic key based on the current timestamp."""
    current_timestamp = int(time.time() // (3 * 60)) * (3 * 60)
    key_data = f"{current_timestamp}".encode()  # Use only the timestamp as key data
    return key_data

def validate_api_token(api_token):
    """Validate the API-Token header using HMAC and the shared secret."""
    try:
        dynamic_key = derive_dynamic_key()
        expected_hash = hmac.new(dynamic_key, b"proxy-access", hashlib.sha256).hexdigest()
        return hmac.compare_digest(api_token, expected_hash)
    except Exception as e:
        if DEBUG:
            print(f"Error validating API-Token: {e}")
        return False

async def handle(request):
    api_token = request.headers.get("API-Token")
    if not api_token or not validate_api_token(api_token):
        return web.Response(text="Unauthorized: i6.shark detected invalid API-Token.", status=401)

    await log_request(request)
    target_url = request.query.get("url")
    if not target_url:
        try:
            cmd = "ip -6 addr show"
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            ipv6_info = stdout.decode()
            print("Current IPv6 configuration:")
            print(ipv6_info)
        except Exception as e:
            print(f"Could not retrieve IPv6 info: {e}")

        return web.Response(text=f"i6.shark is working as expected (v{version}).", status=200)

    headers_json = request.query.get("headers")

    try:
        target_url = ensure_url_has_scheme(target_url)
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return web.Response(text=f"Invalid URL: {target_url}.", status=400)

    try:
        # Check if interface exists first
        if not await check_interface():
            return web.Response(text=f"i6.shark can't find interface {INTERFACE}. Check your configuration.", status=500)
        source_ip = random_ipv6()
        print(f"Using IPv6: {source_ip}")
        # Add IPv6 to interface
        if not await add_ipv6_to_interface(source_ip):
            return web.Response(text="Failed to configure IPv6 address. Root/sudo privileges may be required.", status=500)
        if not await test_ipv6_connectivity(source_ip):
            # Fall back to system default if the IPv6 test fails
            print("Falling back to system default IP")
            connector = aiohttp.TCPConnector()
            source_ip = "System default (fallback)"
        else:
            # Create connector with the configured IPv6
            connector = aiohttp.TCPConnector(local_addr=(source_ip, 0))

        headers = {}
        for name, value in request.headers.items():
            if name.lower() != 'host':
                headers[name] = value

        # Parse and merge custom headers if provided
        if headers_json:
            try:
                import json
                custom_headers = json.loads(headers_json)
                if isinstance(custom_headers, dict):
                    headers.update(custom_headers)
                    if DEBUG:
                        print(f"Applied custom headers: {custom_headers}")
                else:
                    print("Warning: 'headers' parameter is not a valid JSON object. Ignoring.")
            except json.JSONDecodeError:
                print("Warning: Failed to parse 'headers' JSON. Ignoring.")
            except Exception as e:
                print(f"Warning: Error processing 'headers': {e}. Ignoring.")

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            print(f"Connecting to {target_url}...")
            req_method = request.method

            # Handle all HTTP methods
            if req_method == "GET":
                resp = await session.get(target_url, headers=headers)
            elif req_method == "POST":
                body = await request.read()
                resp = await session.post(target_url, data=body, headers=headers)
            elif req_method == "PUT":
                body = await request.read()
                resp = await session.put(target_url, data=body, headers=headers)
            elif req_method == "DELETE":
                resp = await session.delete(target_url, headers=headers)
            elif req_method == "HEAD":
                resp = await session.head(target_url, headers=headers)
            elif req_method == "OPTIONS":
                resp = await session.options(target_url, headers=headers)
            else:
                return web.Response(text=f"i6.shark doesn't support this HTTP method: {req_method}.", status=400)

            print(f"Connected! Status: {resp.status}")

            body = await resp.read()
            response = web.Response(body=body, status=resp.status)
            skip_headers = {
                'transfer-encoding',
                'content-encoding',  # Skip content encoding to avoid browser errors
                'content-length',    # Will be set automatically
                'connection',
                'keep-alive',
                'server',
            }

            for name, value in resp.headers.items():
                if name.lower() not in skip_headers:
                    response.headers[name] = value

            # Log headers we're sending back
            if DEBUG:
                print("Response headers being sent to browser:")
                for name, value in response.headers.items():
                    print(f"  {name}: {value}")

            return response

    except asyncio.TimeoutError:
        return web.Response(text=f"Request timed out connecting to {hostname}.", status=504)
    except aiohttp.ClientConnectorError as e:
        return web.Response(text=f"Connection error to {hostname}: {e}.", status=502)
    except aiohttp.ClientError as e:
        return web.Response(text=f"Client error accessing {hostname}: {e}.", status=502)
    except Exception as e:
        print(f"Unexpected error: {e}")
        return web.Response(text=f"Error: {e}.", status=500)
    finally:
        if 'connector' in locals():
            connector.close()

async def on_startup(app):
    if os.geteuid() != 0 and LISTEN_PORT < 1024:
        print("ERROR: This script requires root privileges to bind to port 80 and add IPv6 addresses")
        print("Run with sudo or change LISTEN_PORT to a value above 1024")
        sys.exit(1)

    print("Testing network configuration...")
    await check_interface()

    test_ip = random_ipv6()
    if not await add_ipv6_to_interface(test_ip):
        print("WARNING: Failed to add IPv6 address for testing. Some features may not work.")

    print("Startup checks completed")

app = web.Application()
app.router.add_get("/", handle)
app.router.add_post("/", handle)  # Support POST requests
app.on_startup.append(on_startup)

if __name__ == "__main__":
    print(f"Starting i6.shark server on {LISTEN_HOST}:{LISTEN_PORT}")
    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT)
