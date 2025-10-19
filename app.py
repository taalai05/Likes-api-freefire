import asyncio
import binascii
import aiohttp
import json
import datetime
import os
import base64
import logging
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from cachetools import TTLCache
from colorama import Fore, Style, init
from typing import Optional, Dict, Any
import requests

# Assuming Protobuf imports remain the same
from Protoo import my_pb2, output_pb2, like_pb2, like_count_pb2, uid_generator_pb2

app = Flask(__name__)
CORS(app)
init(autoreset=True)
cache = TTLCache(maxsize=100, ttl=300)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Move sensitive keys to environment variables
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME", "taalai05")
GITHUB_REPO_NAME = os.environ.get("GITHUB_REPO_NAME", "Likes-api-freefire")
GITHUB_KEYS_FILE = os.environ.get("GITHUB_KEYS_FILE", "keys.json")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "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")
ADMIN_KEY_VALUE = os.environ.get("ADMIN_KEY_VALUE", "Adik")
AES_KEY = os.environ.get("AES_KEY", "Yg&tc%DEuh6%Zc^8").encode()
AES_IV = os.environ.get("AES_IV", "6oyZDr22E3ychjM%").encode()

API_KEYS = []
token_tracker = {}
logging.basicConfig(level=logging.INFO)

# GitHub key management functions (unchanged for brevity, but add error retry logic)
def fetch_keys_from_github():
    if not GITHUB_TOKEN:
        app.logger.error("GITHUB_TOKEN not set.")
        return None
    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_KEYS_FILE}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3.raw"}
    for attempt in range(3):  # Retry logic
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return json.loads(response.text)
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Attempt {attempt+1} failed fetching keys: {e}")
            if attempt == 2:
                return None
            asyncio.sleep(1)

def update_keys_on_github(keys_data):
    if not GITHUB_TOKEN:
        app.logger.error("GITHUB_TOKEN not set.")
        return False
    sha = get_github_file_sha()
    if not sha:
        return False
    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_KEYS_FILE}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Content-Type": "application/json"}
    content = base64.b64encode(json.dumps(keys_data, indent=2).encode()).decode()
    payload = {"message": "Update API keys", "content": content, "sha": sha}
    for attempt in range(3):
        try:
            response = requests.put(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            app.logger.info("keys.json updated successfully.")
            return True
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Attempt {attempt+1} failed updating keys: {e}")
            if attempt == 2:
                return False
            asyncio.sleep(1)

def get_key_status(api_key_str):
    current_keys = fetch_keys_from_github()
    if not current_keys:
        return {"verify": "false", "error": "Service unavailable."}
    current_time = datetime.datetime.now()
    for key_obj in current_keys:
        if key_obj['key'] == api_key_str:
            g.current_key_obj = key_obj
            key_expire_dt = None
            remaining_time_str = "N/A"
            if key_obj.get('time_window_minutes') is not None and key_obj['time_window_minutes'] != -1 and key_obj.get('last_reset'):
                try:
                    last_reset_dt = datetime.datetime.fromisoformat(key_obj['last_reset'])
                    time_elapsed = (current_time - last_reset_dt).total_seconds() / 60
                    if time_elapsed > key_obj['time_window_minutes']:
                        key_obj['usage_count'] = 0
                        key_obj['last_reset'] = current_time.isoformat()
                        update_keys_on_github(current_keys)
                    key_expire_dt = last_reset_dt + datetime.timedelta(minutes=key_obj['time_window_minutes'])
                    time_until_reset = key_expire_dt - current_time
                    if time_until_reset.total_seconds() > 0:
                        total_seconds = int(time_until_reset.total_seconds())
                        remaining_time_str = f"{total_seconds // 60}m {total_seconds % 60}s"
                    else:
                        remaining_time_str = "Expired"
                except ValueError as e:
                    app.logger.error(f"Error parsing last_reset for key {api_key_str}: {e}")
            remaining_limit = "N/A" if key_obj.get('limit') is None or key_obj['limit'] == -1 else max(0, key_obj['limit'] - key_obj['usage_count'])
            if key_obj.get('limit', -1) != -1 and key_obj['usage_count'] >= key_obj['limit']:
                return {
                    "verify": "false",
                    "error": "Usage limit reached.",
                    "key_info": {
                        "remaining_limit": remaining_limit,
                        "key_expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "Never",
                        "remaining_time": remaining_time_str
                    }
                }
            return {
                "verify": "true",
                "key_status": "Active",
                "key_info": {
                    "remaining_limit": remaining_limit,
                    "key_expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "Never",
                    "remaining_time": remaining_time_str
                }
            }
    return {"verify": "false", "error": "Invalid key."}

def update_key_usage(api_key_str, decrement_by=1):
    current_keys = fetch_keys_from_github()
    if not current_keys:
        return False
    for key_obj in current_keys:
        if key_obj['key'] == api_key_str:
            if key_obj.get('limit') is not None and key_obj['limit'] != -1:
                if key_obj.get('last_reset') is None:
                    key_obj['last_reset'] = datetime.datetime.now().isoformat()
                key_obj['usage_count'] += decrement_by
                return update_keys_on_github(current_keys)
            return True
    return False

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=10) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed. Status: {response.status}")
                    return {"status": response.status, "error": await response.text()}
                return {"status": 200, "data": await response.read()}
    except Exception as e:
        app.logger.error(f"Error in send_request: {e}")
        return {"status": 500, "error": str(e)}

async def send_multiple_requests(uid, server_name, url):
    global token_tracker
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if not protobuf_message:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None
        tokens = load_tokens(server_name)
        if not tokens:
            return None
        total_tokens = len(tokens)
        batch_size = min(100, total_tokens)  # Ensure batch_size doesn't exceed available tokens
        if server_name not in token_tracker:
            token_tracker[server_name] = 0
        start_idx = token_tracker[server_name]
        end_idx = (start_idx + batch_size) % total_tokens
        selected_tokens = tokens[start_idx:end_idx] if end_idx > start_idx else tokens[start_idx:] + tokens[:end_idx]
        token_tracker[server_name] = end_idx
        tasks = [send_request(encrypted_uid, token["token"], url) for token in selected_tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == 200)
        return {"success_count": success_count, "results": results}
    except Exception as e:
        app.logger.error(f"Error in send_multiple_requests: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def encrypt_message(plaintext):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

async def make_request_async(encrypt, server_name, token):
    try:
        url = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }.get(server_name, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        result = await send_request(encrypt, token, url)
        if result.get("status") != 200:
            return None
        binary = result["data"]
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        app.logger.error(f"Error in make_request_async: {e}")
        return None

@app.route('/like', methods=['GET'])
async def handle_like():
    api_key = request.args.get("key")
    if not api_key:
        return jsonify([{"verify": "false", "error": "API Key Required."}]), 400

    key_status = get_key_status(api_key)
    if key_status["verify"] == "false":
        error_response = [{"verify": "false", "error": key_status["error"]}]
        if "key_info" in key_status:
            error_response[0].update(key_status["key_info"])
        return jsonify(error_response), 403

    current_key_obj = g.current_key_obj
    uid = request.args.get("uid")
    if not uid:
        return jsonify([{"error": "UID Required."}]), 400

    server_name = request.args.get("region", "bd").upper()
    if server_name not in {"IND", "BR", "US", "SAC", "NA", "BD"}:
        server_name = "BD"

    try:
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify([{"error": "Error loading JWT tokens."}]), 500

        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify([{"error": "UID encryption failed."}]), 500

        # Fetch initial likes
        before = await make_request_async(encrypted_uid, server_name, token)
        if not before:
            return jsonify([{"verify": "true", "error": "Unable to fetch player info. Invalid UID or unsupported region."}]), 400

        try:
            data_before = json.loads(MessageToJson(before))
            before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
        except Exception as e:
            app.logger.error(f"Error converting before protobuf: {e}")
            return jsonify([{"error": f"Protobuf conversion failed: {e}"}]), 500

        app.logger.info(f"Likes before: {before_like} for UID {uid}")

        # Send likes
        url = {
            "IND": "https://client.ind.freefiremobile.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile"
        }.get(server_name, "https://clientbp.ggblueshark.com/LikeProfile")

        result = await send_multiple_requests(uid, server_name, url)
        if not result:
            update_key_usage(api_key, decrement_by=1)
            return jsonify([{
                "verify": "true",
                "remaining limit": current_key_obj['limit'] - current_key_obj['usage_count'] if current_key_obj.get('limit', -1) != -1 else "Unlimited",
                "key expire": (datetime.datetime.fromisoformat(current_key_obj['last_reset']) + 
                               datetime.timedelta(minutes=current_key_obj['time_window_minutes'])).strftime("%d-%m-%Y %H:%M:%S") 
                               if current_key_obj.get('time_window_minutes', -1) != -1 and current_key_obj.get('last_reset') else "N/A",
                "message": "Likes sent but failed to fetch updated data."
            }]), 200

        # Fetch updated likes
        after = await make_request_async(encrypted_uid, server_name, token)
        if not after:
            update_key_usage(api_key, decrement_by=1)
            return jsonify([{
                "verify": "true",
                "remaining limit": current_key_obj['limit'] - current_key_obj['usage_count'] if current_key_obj.get('limit', -1) != -1 else "Unlimited",
                "key expire": (datetime.datetime.fromisoformat(current_key_obj['last_reset']) + 
                               datetime.timedelta(minutes=current_key_obj['time_window_minutes'])).strftime("%d-%m-%Y %H:%M:%S") 
                               if current_key_obj.get('time_window_minutes', -1) != -1 and current_key_obj.get('last_reset') else "N/A",
                "message": "Likes sent but failed to fetch updated data."
            }, {
                "Status": "Partial Success",
                "Player Name": data_before.get('AccountInfo', {}).get('PlayerNickname', 'N/A'),
                "Player UID": int(uid),
                "Likes Before Command": before_like,
                "Likes Added": "Unknown",
                "Likes after": "Unknown"
            }]), 200

        try:
            data_after = json.loads(MessageToJson(after))
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_name = data_after.get('AccountInfo', {}).get('PlayerNickname', 'N/A')
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        except Exception as e:
            app.logger.error(f"Error converting after protobuf: {e}")
            return jsonify([{"error": f"Protobuf conversion failed: {e}"}]), 500

        like_given = after_like - before_like
        key_message = ""
        MIN_LIKES_THRESHOLD = int(os.environ.get("MIN_LIKES_THRESHOLD", 80))

        if like_given >= MIN_LIKES_THRESHOLD:
            update_key_usage(api_key, decrement_by=1)
        elif like_given < MIN_LIKES_THRESHOLD and like_given > 0:
            key_message = "Key limit unchanged due to low likes added."
        elif like_given == 0:
            key_message = "Key limit unchanged. Maximum likes reached for today."

        remaining_limit = "Unlimited" if current_key_obj.get('limit', -1) == -1 else current_key_obj['limit'] - current_key_obj['usage_count']
        key_expire_dt = None
        if current_key_obj.get('time_window_minutes', -1) != -1 and current_key_obj.get('last_reset'):
            last_reset_dt = datetime.datetime.fromisoformat(current_key_obj['last_reset'])
            key_expire_dt = last_reset_dt + datetime.timedelta(minutes=current_key_obj['time_window_minutes'])

        status_message = "Success" if like_given > 0 else "This player already got maximum likes for today."
        response_header = {
            "verify": "true",
            "remaining limit": str(remaining_limit),
            "key expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "N/A"
        }
        if key_message:
            response_header["message"] = key_message

        response_body = {
            "Status": status_message,
            "Player Name": player_name,
            "Player UID": player_uid,
            "Likes Before Command": before_like,
            "Likes Added": str(like_given) if like_given > 0 else "N/A",
            "Likes after": after_like
        }
        if like_given == 0:
            del response_body["Likes Added"]
            response_body["Current Likes"] = before_like
            del response_body["Likes Before Command"]
            del response_body["Likes after"]

        return jsonify([response_header, response_body]), 200

    except Exception as e:
        app.logger.error(f"Error processing like request for UID {uid}: {e}")
        return jsonify([{"verify": "false", "error": str(e)}]), 500

if __name__ == '__main__':
    initial_keys = fetch_keys_from_github()
    if initial_keys:
        API_KEYS = initial_keys
        app.logger.info("Initial API keys loaded from GitHub.")
    else:
        app.logger.error("Failed to load API keys from GitHub.")
    app.run(debug=True, port=int(os.environ.get("PORT", 8080)))



