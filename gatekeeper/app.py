import os
import uuid
import redis
import requests
from flask import Flask, request, Response, make_response
from dotenv import load_dotenv

# Load config from .env
load_dotenv()

# --- Configuration ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT_SECONDS", 3600)) # 60 mins
APP_PORT = os.getenv("APP_TARGET_PORT", 80)

# Get the list of target containers from the env file
APP_TARGETS = os.getenv("APP_TARGETS", "").split(',')
if not all(APP_TARGETS):
    raise ValueError("APP_TARGETS is not set in the .env file")

print(f"Gatekeeper starting...")
print(f"Session Timeout: {SESSION_TIMEOUT} seconds")
print(f"Managing targets: {APP_TARGETS}")

# --- Initialize ---
app = Flask(__name__)
r = redis.Redis(host=REDIS_HOST, port=6379, db=0)

# --- Define Keys ---
# We use Redis keys to track state:
# "session:{session_id}" -> "my-app-1" (Maps user's session to a container)
# "container-lock:{container_name}" -> "session:{session_id}" (Locks container)


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
    target_host = None

    # 1. Check for existing valid session
    if session_id:
        session_key = f"session:{session_id}"
        target_host_bytes = r.get(session_key)
        
        if target_host_bytes:
            target_host = target_host_bytes.decode('utf-8')
            
            # This is a valid, active user. Refresh their session.
            print(f"Refreshing session {session_id} for {target_host}")
            r.expire(session_key, SESSION_TIMEOUT)
            r.expire(f"container-lock:{target_host}", SESSION_TIMEOUT)
        else:
            # User has a cookie, but the session expired in Redis.
            # Treat them as a new user.
            print(f"Stale session cookie found: {session_id}")
            session_id = None

    # 2. No valid session. Find a new container.
    if not session_id:
        print("No valid session. Attempting to find free container...")
        for host in APP_TARGETS:
            lock_key = f"container-lock:{host}"
            
            # Atomically try to acquire a lock with the 60-min timeout.
            # 'nx=True' means "set only if it does not exist".
            lock_acquired = r.set(lock_key, "in-use", ex=SESSION_TIMEOUT, nx=True)
            
            if lock_acquired:
                # We got a container!
                session_id = str(uuid.uuid4())
                target_host = host
                session_key = f"session:{session_id}"

                # Link session_id to host and update lock with session_id
                r.set(session_key, target_host, ex=SESSION_TIMEOUT)
                r.set(lock_key, session_key, ex=SESSION_TIMEOUT) # Overwrite "in-use"
                
                print(f"Assigned {target_host} to new session {session_id}")
                break
        
        if not target_host:
            # 3. All containers are busy
            print("All containers are busy.")
            return "Sorry, all sessions are currently busy. Please try again later.", 503

    # 4. We have a target_host and session_id. Proxy the request.
    try:
        url = f"http://{target_host}:{APP_PORT}/{path}"
        
        # Stream the proxy request to handle large files / long-polling
        proxy_resp = requests.request(
            method=request.method,
            url=url,
            params=request.args,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True
        )
    except requests.exceptions.ConnectionError:
        print(f"Error: Gatekeeper could not connect to upstream host {target_host}")
        return "Application container is not responding.", 502

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
