import os
import uuid
import redis.asyncio as aioredis
from aiohttp import web, ClientSession, DummyCookieJar, TCPConnector
from dotenv import load_dotenv
import ssl
import asyncio
from OpenSSL import crypto

# --- Configuration ---
load_dotenv()
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT_SECONDS", 3600))
APP_TARGETS = os.getenv("APP_TARGETS", "").split(',')
if not all(APP_TARGETS):
    raise ValueError("APP_TARGETS is not set in the .env file")

APP_VERIFY_SSL_RAW = os.getenv("APP_TARGET_VERIFY_SSL", "True")
APP_VERIFY_SSL = APP_VERIFY_SSL_RAW.lower() in ('true', '1', 't', 'yes')

if not APP_VERIFY_SSL:
    print("WARNING: Upstream SSL certificate verification is disabled.")

print(f"Gatekeeper starting...")
print(f"Session Timeout: {SESSION_TIMEOUT} seconds")
print(f"Managing targets: {APP_TARGETS}")

# Headers to exclude when proxying
EXCLUDED_HEADERS = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}

async def get_or_create_session(request):
    """
    Handles the core Redis logic to get an existing session
    or find and lock a new one.
    """
    r = request.app['redis']
    session_id = request.cookies.get('session_id')
    target_base_url = None
    is_new_session = False

    # 1. Check for existing valid session
    if session_id:
        session_key = f"session:{session_id}"
        target_base_url_bytes = await r.get(session_key)
        if target_base_url_bytes:
            target_base_url = target_base_url_bytes.decode('utf-8')
            print(f"Refreshing session {session_id} for {target_base_url}")
            await r.expire(session_key, SESSION_TIMEOUT)
            await r.expire(f"container-lock:{target_base_url}", SESSION_TIMEOUT)
        else:
            print(f"Stale session cookie found: {session_id}")
            session_id = None

    # 2. No valid session. Find a new container.
    if not session_id:
        print("No valid session. Attempting to find free container...")
        is_new_session = True
        for base_url in APP_TARGETS:
            lock_key = f"container-lock:{base_url}"
            lock_acquired = await r.set(lock_key, "in-use", ex=SESSION_TIMEOUT, nx=True)
            if lock_acquired:
                session_id = str(uuid.uuid4())
                target_base_url = base_url
                session_key = f"session:{session_id}"
                await r.set(session_key, target_base_url, ex=SESSION_TIMEOUT)
                await r.set(lock_key, session_key, ex=SESSION_TIMEOUT)
                print(f"Assigned {target_base_url} to new session {session_id}")
                break

    return target_base_url, session_id, is_new_session

async def proxy_http_request(request, target_url):
    """
    Handles a standard HTTP (GET, POST, etc.) request.
    It reads the full body, makes the proxy request,
    and sends the full response.
    """
    session = request.app['client_session']
    headers = {k: v for k, v in request.headers.items() if k.lower() not in EXCLUDED_HEADERS}
    
    try:
        async with session.request(
            request.method,
            target_url,
            params=request.query,
            headers=headers,
            data=await request.read()
        ) as proxy_resp:
            
            body = await proxy_resp.read()
            response_headers = {
                k: v for k, v in proxy_resp.headers.items() 
                if k.lower() not in EXCLUDED_HEADERS
            }
            
            return web.Response(
                body=body,
                status=proxy_resp.status,
                headers=response_headers
            )
            
    except Exception as e:
        print(f"HTTP Proxy Error: {e}")
        return web.Response(text="Application container is not responding.", status=502)

async def proxy_websocket_request(request, target_base_url):
    """
    Handles a WebSocket upgrade request.
    It creates a WebSocket to the client AND a WebSocket
    to the backend, then proxies messages between them.
    """
    session = request.app['client_session']
    
    # Prepare the client-facing WebSocket
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)
    
    # Prepare the backend-facing WebSocket URL
    ws_url_base = target_base_url.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url_base}{request.path_qs}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'connection', 'upgrade']}

    print(f"Attempting WebSocket connection to: {ws_url}")

    try:
        async with session.ws_connect(
            ws_url,
            headers=headers
        ) as server_ws:
            
            print("WebSocket connection established.")

            # Bi-directional proxy tasks
            async def forward_client_to_server():
                async for msg in client_ws:
                    if msg.type == web.WSMsgType.BINARY:
                        await server_ws.send_bytes(msg.data)
                    elif msg.type == web.WSMsgType.TEXT:
                        await server_ws.send_str(msg.data)
                await server_ws.close()

            async def forward_server_to_client():
                async for msg in server_ws:
                    if msg.type == web.WSMsgType.BINARY:
                        await client_ws.send_bytes(msg.data)
                    elif msg.type == web.WSMsgType.TEXT:
                        await client_ws.send_str(msg.data)
                await client_ws.close()

            # Run both proxy tasks concurrently
            await asyncio.gather(
                forward_client_to_server(),
                forward_server_to_client()
            )
            
    except Exception as e:
        print(f"WebSocket Proxy Error: {e}")
        await client_ws.close(code=1011, message="Proxy error")
    
    finally:
        print("WebSocket connection closed.")
        
    return client_ws

async def gatekeeper_handler(request):
    """
    Main request handler for ALL traffic.
    """
    # 1. Get session and target URL from Redis
    target_base_url, session_id, is_new_session = await get_or_create_session(request)

    if not target_base_url:
        return web.Response(text="Sorry, all sessions are currently busy.", status=503)

    # 2. Check if it's a WebSocket upgrade request
    is_websocket = (
        'Upgrade' in request.headers and
        request.headers.get('Upgrade', '').lower() == 'websocket'
    )

    # 3. Handle WebSocket
    if is_websocket:
        return await proxy_websocket_request(request, target_base_url)
    
    # 4. Handle standard HTTP
    else:
        # Build the final URL, cleaning up slashes
        clean_base = target_base_url.rstrip('/')
        clean_path = request.path.lstrip('/')
        target_url = f"{clean_base}/{clean_path}"
        
        response = await proxy_http_request(request, target_url)
        
        # 5. Set session cookie if this is a new session
        if is_new_session:
            response.set_cookie(
                'session_id',
                session_id,
                max_age=SESSION_TIMEOUT,
                httponly=True,
                path='/'
            )
        return response

def create_self_signed_cert():
    """Generates a self-signed cert and key for the HTTPS server."""
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().C = "CZ"
    cert.get_subject().ST = "Prague"
    cert.get_subject().L = "Prague"
    cert.get_subject().O = "Gatekeeper"
    cert.get_subject().OU = "Gatekeeper"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60) # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha26')

    # Save to files
    key_file = "gatekeeper_key.pem"
    cert_file = "gatekeeper_cert.pem"
    
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
    return cert_file, key_file

async def main():
    """Main startup function."""
    
    # Create SSL context for the *upstream* (proxy client)
    # This respects APP_TARGET_VERIFY_SSL=False
    client_ssl_context = ssl.create_default_context()
    if not APP_VERIFY_SSL:
        client_ssl_context.check_hostname = False
        client_ssl_context.verify_mode = ssl.CERT_NONE
        
    client_session = ClientSession(
        cookie_jar=DummyCookieJar(),
        connector=TCPConnector(ssl=client_ssl_context)
    )
    
    # Create SSL context for the *downstream* (our server)
    cert_file, key_file = create_self_signed_cert()
    server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # Create the application
    app = web.Application()
    app['redis'] = aioredis.from_url(f"redis://{REDIS_HOST}")
    app['client_session'] = client_session
    
    # Add the main handler
    app.router.add_route("*", "/{path:.*}", gatekeeper_handler)

    # Set up the server runner
    runner = web.AppRunner(app)
    await runner.setup()
    
    # Create and start both HTTP and HTTPS sites
    http_site = web.TCPSite(runner, '0.0.0.0', 5000)
    https_site = web.TCPSite(runner, '0.0.0.0', 5001, ssl_context=server_ssl_context)
    
    await http_site.start()
    print("Started HTTP server on http://0.0.0.0:5000")
    
    await https_site.start()
    print("Started HTTPS server on https://0.0.0.0:5001")

    # Wait forever
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down...")
