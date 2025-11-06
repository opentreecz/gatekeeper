import os
import uuid
import redis
import requests
from flask import Flask, request, Response, make_response
from dotenv import load_dotenv
import urllib3  # <-- NEW: Import urllib3 to manage SSL warnings

# Load config from .env
load_dotenv()

# --- Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT_SECONDS", 3600)) # 60 mins

# --- REMOVED ---
# APP_PORT is no longer needed; it's defined in APP_TARGETS

# --- UPDATED ---
# Get the list of full URL targets from the env file
APP_TARGETS = os.getenv("APP_TARGETS", "").split(',')
if not all(APP_TARGETS):
    raise ValueError("APP_TARGETS is not set in the .env file")

# --- NEW ---
# Check for SSL verification. Convert string "False" to boolean False.
APP_VERIFY_SSL_RAW = os.getenv("APP_TARGET_VERIFY_SSL", "True")
APP_VERIFY_SSL = APP_VERIFY_SSL_RAW.lower() in ('true', '1', 't', 'yes')

# --- NEW ---
# If SSL verification is disabled, also disable the console warnings
if not APP_VERIFY_SSL:
    print("WARNING: SSL certificate verification is disabled.")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


print(f"Gatekeeper starting...")
print(f"Session Timeout: {SESSION_TIMEOUT} seconds")
print(f"Managing targets: {APP_TARGETS}")

# --- Initialize ---
app = Flask(__name__)
r = redis.Redis(host=REDIS_HOST, port=6379, db=0)

# --- Define Keys ---
# "session:{session_id}" -> "https://my-app-1:443" (Maps user's session to a full URL)
# "container-lock:{base_url}" -> "session:{session_id}" (Locks container)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def gatekeeper(path):
    """
    Main route handler.
    1. Checks for an existing, valid session cookie.
    2. If valid, refreshes its timeout and proxies to the correct container.
    3. If invalid or missing, tries to find and lock a free container.
    4. If no containers are free, returns a 503 error.
    """
    session_id = request.cookies.get('session_id')
    target_base_url = None # <-- Renamed from target_host for clarity

    # 1. Check for existing valid session
    if session_id:
        session_key = f"session:{session_id}"
        target_base_url_bytes = r.get(session_key)
        
        if target_base_url_bytes:
            target_base_url = target_base_url_bytes.decode('utf-8')
            
            # This is a valid, active user. Refresh their session.
            print(f"Refreshing session {session_id} for {target_base_url}")
            r.expire(session_key, SESSION_TIMEOUT)
            r.expire(f"container-lock:{target_base_url}", SESSION_TIMEOUT)
        else:
            # User has a cookie, but the session expired in Redis.
            # Treat them as a new user.
            print(f"Stale session cookie found: {session_id}")
            session_id = None

    # 2. No valid session. Find a new container.
    if not session_id:
        print("No valid session. Attempting to find free container...")
        for base_url in APP_TARGETS: # <-- Renamed from host
            lock_key = f"container-lock:{base_url}"
            
            # Atomically try to acquire a lock with the 60-min timeout.
            # 'nx=True' means "set only if it does not exist".
            lock_acquired = r.set(lock_key, "in-use", ex=SESSION_TIMEOUT, nx=True)
            
            if lock_acquired:
                # We got a container!
                session_id = str(uuid.uuid4())
                target_base_url = base_url
                session_key = f"session:{session_id}"

                # Link session_id to host and update lock with session_id
                r.set(session_key, target_base_url, ex=SESSION_TIMEOUT)
                r.set(lock_key, session_key, ex=SESSION_TIMEOUT) # Overwrite "in-use"
                
                print(f"Assigned {target_base_url} to new session {session_id}")
                break
        
        if not target_base_url:
            # 3. All containers are busy
            print("All containers are busy.")
            return "Sorry, all sessions are currently busy. Please try again later.", 503

    # 4. We have a target_base_url and session_id. Proxy the request.
    try:
        # --- UPDATED ---
        # target_base_url is now the full URL (e.g., "https://my-app-1:443")
        url = f"{target_base_url}/{path}"
        
        # Stream the proxy request to handle large files / long-polling
        proxy_resp = requests.request(
            method=request.method,
            url=url,
            params=request.args,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            verify=APP_VERIFY_SSL  # <-- NEW: Add SSL verification flag
        )
    except requests.exceptions.ConnectionError:
        # --- UPDATED ---
        # More informative error log
        print(f"Error: Gatekeeper could not connect to upstream URL {url}")
        return "Application container is not responding.", 502
    except requests.exceptions.SSLError as e:
        print(f"Error: SSL Error connecting to {url}. Details: {e}")
        print("If using self-signed certs, set APP_TARGET_VERIFY_SSL=False in .env")
        return "Application container SSL error.", 502

    # 5. Stream the response back to the client
    # We must exclude certain headers that are set by the proxy
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [
        (name, value) for (name, value) in proxy_resp.raw.headers.items()
        if name.lower() not in excluded_headers
    ]

    response = Response(proxy_resp.iter_content(8192), proxy_resp.status_code, headers)

    # Set the session cookie on the response
    response.set_cookie(
        'session_id',
        session_id,
        max_age=SESSION_TIMEOUT,
        httponly=True, # Recommended for security
        path='/'
    )
    return response

if __name__ == '__main__':
    # This is for local dev, not for production
    app.run(debug=True, host='0.0.0.0', port=5000)
