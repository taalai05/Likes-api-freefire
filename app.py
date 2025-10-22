# -------------------------------------------------------- !!
# --------->> API LIEKS !! DO NOT SHARE BRO !! <3 -------- !!
# -------------------------------------------------------- !!

import asyncio
import binascii
import aiohttp
import requests
import json
import random
import secrets
import threading
import datetime
import time
import os
import base64
import warnings
import logging
import urllib3
import string

from Protoo import my_pb2                      # --------->> Set Protobuf Files in a Different Folder
from Protoo import output_pb2                  # --------->> Set Protobuf Files in a Different Folder
from Protoo import like_pb2                    # --------->> Set Protobuf Files in a Different Folder
from Protoo import like_count_pb2              # --------->> Set Protobuf Files in a Different Folder
from Protoo import uid_generator_pb2           # --------->> Set Protobuf Files in a Different Folder
from protobuf_parser import Parser, Utils   

from functools import wraps
from functools import lru_cache
from cachetools import TTLCache
from typing import Optional, Dict, Any
from colorama import Fore, Style, init
from urllib3.exceptions import InsecureRequestWarning

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from google.protobuf.json_format import MessageToJson
from google.protobuf.descriptor_pb2 import DescriptorProto, FieldDescriptorProto
from google.protobuf.descriptor import MakeDescriptor
from google.protobuf.message_factory import GetMessageClass
from google.protobuf.message import DecodeError
from google.protobuf.json_format import MessageToDict, MessageToJson

from flask import Flask, redirect, url_for, request, jsonify, Response, g
from flask_cors import CORS


app = Flask(__name__)

CORS(app)
init(autoreset=True)
cache = TTLCache(maxsize=100, ttl=300)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# ---->> GITHUB Info - For Store API Keys.

GITHUB_USERNAME = "taalai05"         # -------->> Github Username.
GITHUB_REPO_NAME = "Likes-apis-freefire"             # -------->> Github Repo Name - Where to save keys.
GITHUB_KEYS_FILE = "keys.json"          # -------->> Create a file to store Keys.
GITHUB_TOKEN = "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"      # -------->> Your Github Personal Access Token.

API_KEYS = []
LAST_KEYS_UPDATE = None
ADMIN_KEY_VALUE = "Adik"                 # -------->> ADMIN Key to Add / Remove Keys in API - With Limit 

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# ------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------- #

# ------------------------>> API KEYS ADD/REMOVE/VALIDATE (MONTHLY LIMIT) <<----------------------------- #

# ------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------- #

def fetch_keys_from_github():

    if not GITHUB_TOKEN:
        app.logger.error("GITHUB_TOKEN environment variable not set. Key management will not work.")
        return None

    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_KEYS_FILE}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.raw"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return json.loads(response.text)

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching keys from GitHub: {e}")
        return None

def get_github_file_sha():

    if not GITHUB_TOKEN:
        return None

    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_KEYS_FILE}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("sha")

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error getting SHA of keys.json from GitHub: {e}")
        return None

def update_keys_on_github(keys_data):

    if not GITHUB_TOKEN:
        app.logger.error("GITHUB_TOKEN environment variable not set. Cannot update keys on GitHub.")
        return False

    sha = get_github_file_sha()
    if not sha:
        app.logger.error("Could not get current SHA of keys.json. Cannot update.")
        return False

    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_KEYS_FILE}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    content = base64.b64encode(json.dumps(keys_data, indent=2).encode('utf-8')).decode('utf-8')
    payload = {
        "message": "Update API keys",
        "content": content,
        "sha": sha
    }
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        app.logger.info("keys.json updated successfully on GitHub.")
        return True

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error updating keys on GitHub: {e}")
        app.logger.error(f"GitHub API response: {response.text if 'response' in locals() else 'N/A'}")
        return False

def get_key_status(api_key_str):
    current_keys = fetch_keys_from_github()
    
    if not current_keys:
        app.logger.error("Failed to fetch keys from GitHub. Cannot verify API key.")
        return {"verify": "false", "error": "Service temporarily unavailable. Please try again later."}

    current_time = datetime.datetime.now()

    for key_obj in current_keys:
        if key_obj['key'] == api_key_str:
            g.current_key_obj = key_obj
            key_expire_dt = None
            remaining_time_str = "N/A"      # ---->> DEFAULT TIME. YOU CAN CHANGE IT.

            if key_obj.get('time_window_minutes') is not None and key_obj['time_window_minutes'] != -1 and key_obj.get('last_reset'):
                try:
                    last_reset_dt = datetime.datetime.fromisoformat(key_obj['last_reset'])
                    time_elapsed = (current_time - last_reset_dt).total_seconds() / 60
                    if time_elapsed > key_obj['time_window_minutes']:
                        app.logger.info(f"Key {api_key_str} time window expired. Attempting to reset usage and persist.")
                        key_obj['usage_count'] = 0
                        key_obj['last_reset'] = current_time.isoformat()
                        if update_keys_on_github(current_keys):
                            app.logger.info(f"Successfully reset and persisted key {api_key_str} on GitHub.")
                        else:
                            app.logger.error(f"Failed to reset and persist key {api_key_str} on GitHub. "
                                             "Key might remain limited until next successful fetch/update.")
                except ValueError as e:
                    app.logger.error(f"Error parsing 'last_reset' for key {api_key_str}: {e}. Skipping time window check.")

            if key_obj.get('time_window_minutes') is not None and key_obj['time_window_minutes'] != -1 and key_obj.get('last_reset'):
                try:
                    last_reset_dt = datetime.datetime.fromisoformat(key_obj['last_reset'])
                    key_expire_dt = last_reset_dt + datetime.timedelta(minutes=key_obj['time_window_minutes'])
                    time_until_reset = key_expire_dt - current_time

                    if time_until_reset.total_seconds() > 0:
                        total_seconds_until_reset = int(time_until_reset.total_seconds())
                        minutes = total_seconds_until_reset // 60
                        seconds = total_seconds_until_reset % 60
                        remaining_time_str = f"{minutes}m {seconds}s"
                    else:
                        remaining_time_str = "Expired (due for reset)"
                except ValueError as e:
                    app.logger.error(f"Error calculating key_expire_dt for key {api_key_str}: {e}.")
                    key_expire_dt = None 
                    remaining_time_str = "Error calculating time"

            remaining_limit = "N/A"
            if key_obj.get('limit') is not None and key_obj['limit'] != -1:
                remaining_limit = max(0, key_obj['limit'] - key_obj['usage_count'])

            if key_obj.get('limit') is not None and key_obj['limit'] != -1 and key_obj['usage_count'] >= key_obj['limit']:
                return {
                    "verify": "false",
                    "error": "Your usage limit has been reached. Please contact your API Provider.",
                    "key_info": {
                        "remaining_limit": remaining_limit,
                        "key_expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "Never",
                        "remaining_time": remaining_time_str
                    }
                }
            else:
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
        app.logger.error("Failed to fetch keys from GitHub for usage update. Cannot update key.")
        return False

    found_key = False
    for key_obj in current_keys:
        if key_obj['key'] == api_key_str:
            found_key = True
            if key_obj.get('limit') is not None and key_obj['limit'] != -1: 
                if key_obj.get('last_reset') is None:
                    key_obj['last_reset'] = datetime.datetime.now().isoformat()
                
                key_obj['usage_count'] += decrement_by
                app.logger.info(f"Key {api_key_str} usage count updated to {key_obj['usage_count']}")
                
                if update_keys_on_github(current_keys):
                    app.logger.info(f"Successfully persisted usage for key {api_key_str} to GitHub.")
                    return True

                else:
                    app.logger.error(f"Failed to persist usage for key {api_key_str} to GitHub. "
                                     "The usage count on GitHub might be inconsistent with the local check.")
                    return False
            else:
                app.logger.info(f"Key {api_key_str} has no limit set ('limit' is -1 or missing), usage not tracked.")
                return True
    
    if not found_key:
        app.logger.warning(f"Attempted to update usage for non-existent key: {api_key_str}")
    return False

# ------------------------------------------------------------------------------------------------------- #
# ------------------------------------------------------------------------------------------------------- #

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens. Log: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message. Log: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Exception in create_protobuf_message. Log: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"            # --------------->> CHANGE IN EVERY OB UPDATE.
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed. Status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request. Log: {e}")
        return None

token_tracker = {}

async def send_multiple_requests(uid, server_name, url):
    global token_tracker
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Error: Failed to create protobuf message.")
            return None

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Error: UID Encryption failed.")
            return None

        tokens = load_tokens(server_name)
        if tokens is None or len(tokens) < 0:         # ------>> CHECKS FOR MINIMUM TOKENS. 0 MEANS IT WILL WORK WITH 1 TOKENS TOO.
            app.logger.error("Error: Insufficient tokens available.")
            return None

        total_tokens = len(tokens)
        batch_size = 1000
        if server_name not in token_tracker:
            token_tracker[server_name] = 0

        start_idx = token_tracker[server_name]
        end_idx = start_idx + batch_size
        if end_idx > total_tokens:
            selected_tokens = tokens[start_idx:] + tokens[:end_idx % total_tokens]
            token_tracker[server_name] = end_idx % total_tokens
        else:
            selected_tokens = tokens[start_idx:end_idx]
            token_tracker[server_name] = end_idx  
        tasks = [send_request(encrypted_uid, token["token"], url) for token in selected_tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests. Log: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf. Log: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        print(f"Protobuf Data returned None")
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data. Log: {e}")
        return 
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding. Log: {e}")
        return

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request. Log: {e}")
        return None


def get_token(password, uid):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    max_retries = 15
    retry_count = 0

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            return None
        return response.json()
    except Exception as e:
        print(f"Error fetching token: {e}")
        return None

def encrypt_message_jwt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def parse_response(response_content):
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {"error": "err_too_many_requests"}
    if 'open_id' not in token_data or 'access_token' not in token_data:
        return {"uid": uid, "error": "invalid uid or password"}
    
    # Create GameData Protobuf
    game_data = my_pb2.GameData()
    game_data.timestamp = "2025-05-28 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.111.5"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|090ad200-5ad8-43b4-9262-96ff785152ec"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"    
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019118397"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="    
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()

    encrypted_data = encrypt_message_jwt(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                return {
                    "uid": uid,
                    "token": response_dict.get("token", "N/A")
                }
            except Exception as e:
                return {
                    "uid": uid,
                    "error": f"Failed to deserialize the response: {e}"
                }
        else:
            return {
                "uid": uid,
                "error": f"Failed to get response: HTTP {response.status_code}, {response.reason}"
            }
    except requests.RequestException as e:
        return {
            "uid": uid,
            "error": f"An error occurred while making the request: {e}"
        }

# ---------------------------------------------------------------------- #
# ---------------------------------------------------------------------- #

# ------>> API Route: /jwt?uid={}&password=
@app.route('/jwt', methods=['GET'])
def get_responses():

    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"error": "Write the guest100067.dat file UID and Password. Usage: /jwt?uid=&password="}), 400

    responses = []
    response = process_token(uid, password)
    responses.append(response)

    return jsonify(responses), 200


# ------>> API Route: /like?key={}&uid={}&region={}
# ------>> If Region not selected, it will auto choose Region - SG (token_bd.json)

@app.route('/like', methods=['GET'])
def handle_like():

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

    server_name = request.args.get("region", "bd")
    if not server_name:
        server_name = "Sg"

    try:
        tokens = load_tokens(server_name)
        if tokens is None:
            return jsonify([{"error": "Error Loading JWT Tokens. Contact with your API Provider for this issue."}]), 500
        
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify([{"error": "Encryption of UID failed."}]), 500

        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            return jsonify([{"verify": "true", "error": "Unable to fetch player info. Invalid UID or Unsupported Region."}]), 400
        
        try:
            jsone = MessageToJson(before)
        except Exception as e:
            return jsonify([{"error": f"Error converting 'before' protobuf to JSON. Error Log: {e}"}]), 500
        
        data_before = json.loads(jsone)
        before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
        try:
            before_like = int(before_like)
        except Exception:
            before_like = 0
        app.logger.info(f"Likes before command: {before_like}")

        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"

        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"

        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))
        after = make_request(encrypted_uid, server_name, token)

        if after is None:
            update_key_usage(api_key, decrement_by=1)   # --------->> Count limit if API Can't get Data after Sending Likes.
            key_expire_dt = None
            if current_key_obj.get('time_window_minutes') != -1 and current_key_obj.get('last_reset'):
                 last_reset_dt = datetime.datetime.fromisoformat(current_key_obj['last_reset'])
                 key_expire_dt = last_reset_dt + datetime.timedelta(minutes=current_key_obj['time_window_minutes'])

            return jsonify([
                {
                    "verify": "true",
                    "remaining limit": current_key_obj['limit'] - current_key_obj['usage_count'],
                    "key expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "N/A",
                    "message": "Like sent Successfully. But there was an issue while fatching the Account Data After Sending Likes."
                },
                {
                    "Status": "Partial Success",
                    "Player Name": data_before.get('AccountInfo', {}).get('PlayerNickname', 'N/A'),
                    "Player UID": int(uid),
                    "Likes Before Command": before_like,
                    "Likes Added": "Unknown (data fetch failed)",
                    "Likes after": "Unknown (data fetch failed)"
                }
            ]), 200

        try:
            jsone_after = MessageToJson(after)
        except Exception as e:
            update_key_usage(api_key, decrement_by=1)
            key_expire_dt = None
            if current_key_obj.get('time_window_minutes') != -1 and current_key_obj.get('last_reset'):
                 last_reset_dt = datetime.datetime.fromisoformat(current_key_obj['last_reset'])
                 key_expire_dt = last_reset_dt + datetime.timedelta(minutes=current_key_obj['time_window_minutes'])

            return jsonify([
                {
                    "verify": "true",
                    "remaining limit": current_key_obj['limit'] - current_key_obj['usage_count'],
                    "key expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "N/A",
                    "message": f"Like was sent successfully but there was a problem converting 'after' data. Error Log: {e}"
                },
                {
                    "Status": "Partial Success",
                    "Player Name": data_before.get('AccountInfo', {}).get('PlayerNickname', 'N/A'),
                    "Player UID": int(uid),
                    "Likes Before Command": before_like,
                    "Likes Added": "Unknown (data conversion failed)",
                    "Likes after": "Unknown (data conversion failed)"
                }
            ]), 200

        data_after = json.loads(jsone_after)
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        like_given = after_like - before_like
        key_message = ""

        if like_given >= 80:                            # ------------->> MINIMUM LIKES COUNT TO REDUCE LIMIT OF A KEY.
            update_key_usage(api_key, decrement_by=1)
        elif like_given < 80 and like_given > 0:
            key_message = "Your key limit remains unchanged because of low likes issue."
        elif like_given == 0:
            key_message = "Your key limit remains unchanged."

        remaining_limit = "Unlimited"
        if current_key_obj['limit'] != -1:
            remaining_limit = current_key_obj['limit'] - current_key_obj['usage_count']

        key_expire_dt = None
        if current_key_obj.get('time_window_minutes') != -1 and current_key_obj.get('last_reset'):
             last_reset_dt = datetime.datetime.fromisoformat(current_key_obj['last_reset'])
             key_expire_dt = last_reset_dt + datetime.timedelta(minutes=current_key_obj['time_window_minutes'])

        status_message = "Success"
        if like_given == 0:
            status_message = "This player already got Maximum likes for today."
            
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
            "Likes Added": str(like_given) if like_given != 0 else "N/A", 
            "Likes after": after_like
        }
        
        if like_given == 0: 
            del response_body["Likes Added"]
            response_body["Current Likes"] = before_like
            del response_body["Likes Before Command"]
            del response_body["Likes after"]

        return jsonify([response_header, response_body])

    except Exception as e:
        app.logger.error(f"Error processing request for UID {uid}: {e}")
        return jsonify([{"verify": "false", "error": str(e)}]), 500

# ---------------------------------------------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------------------------------------------- #

# --------->> ADD API KEYS: /addkey?admin={AdminKey}&key={New User Key}&limit={Monthly Limit}&time={Days}

@app.route('/addkey', methods=['GET'])
def add_key():
    admin_key = request.args.get("admin")
    new_key_value = request.args.get("key")
    limit_str = request.args.get("limit")
    time_str = request.args.get("time")
    
    if admin_key != ADMIN_KEY_VALUE:
        return jsonify({"Error": "Unauthorized. Invalid admin key."}), 403

    if not new_key_value or not limit_str or not time_str:
        return jsonify({"Error": "Missing parameters. Required: key, limit, time."}), 400

    try:
        limit = int(limit_str)
        time_days = int(time_str)
        time_minutes = time_days * 24 * 60 
    except ValueError:
        return jsonify({"Error": "Limit and time must be integers."}), 400
    
    current_keys = fetch_keys_from_github()
    if current_keys is None:
        app.logger.error("Failed to fetch current keys from GitHub. Cannot add new key.")
        return jsonify({"error": "Service temporarily unavailable. Could not fetch existing keys."}), 500

    if any(k['key'] == new_key_value for k in current_keys):
        return jsonify({"Error": f"Key '{new_key_value}' already exists."}), 409 

    new_key_obj = {
        "key": new_key_value,
        "limit": limit,
        "time_window_minutes": time_minutes,
        "usage_count": 0,
        "last_reset": None,
        "is_admin": False
    }
    
    current_keys.append(new_key_obj)
    if update_keys_on_github(current_keys):
        return jsonify({"message": f"Key '{new_key_value}' added successfully.", "key_details": new_key_obj}), 200
    else:
        return jsonify({"error": "Failed to add key to GitHub. Please try again."}), 500


# --------->> Remove API Keys: /addkey?admin={AdminKey}&key={New User Key}
@app.route('/removekey', methods=['GET'])
def remove_key():
    global API_KEYS
    admin_key = request.args.get("admin")
    key_to_remove = request.args.get("key")

    if admin_key != ADMIN_KEY_VALUE:
        return jsonify({"Error": "Unauthorized. Invalid admin key."}), 403

    if not key_to_remove:
        return jsonify({"Error": "Missing 'key' parameter."}), 400

    original_key_count = len(API_KEYS) 
    updated_keys = [k for k in API_KEYS if k['key'] != key_to_remove] 
    API_KEYS = updated_keys

    if len(updated_keys) == original_key_count:
        return jsonify({"Error": f"Key '{key_to_remove}' not found."}), 404

    if update_keys_on_github(API_KEYS):
        return jsonify({"message": f"Key '{key_to_remove}' removed successfully."}), 200

    else:
        return jsonify({"error": "Failed to remove key from GitHub. Please try again."}), 500


# --------->> Check Key Status: /status?key={New User Key}
@app.route('/status', methods=['GET'])
def get_key_status_endpoint():

    api_key = request.args.get("key")
    if not api_key:
        return jsonify({"verify": "false", "error": "API Key Required."}), 400

    current_keys = fetch_keys_from_github()
    if not current_keys:
        app.logger.error("Failed to fetch keys from GitHub for status endpoint.")
        return jsonify({"verify": "false", "error": "Service temporarily unavailable. Could not load keys."}), 500

    found_key = None
    for key_obj in current_keys:
        if key_obj['key'] == api_key:
            found_key = key_obj
            break
    
    if not found_key:
        return jsonify({"verify": "false", "error": "Invalid key."}), 404

    status_message = "Active"
    remaining_limit = "N/A" 
    key_expire_dt = None
    remaining_time_str = "N/A"

    if found_key.get('limit') is not None and found_key['limit'] != -1:
        remaining_limit = max(0, found_key['limit'] - found_key['usage_count'])
        if remaining_limit == 0:
            status_message = "Limit Reached" 

    if found_key.get('time_window_minutes') is not None and found_key['time_window_minutes'] != -1 and found_key.get('last_reset'):
        try:
            last_reset_dt = datetime.datetime.fromisoformat(found_key['last_reset'])
            key_expire_dt = last_reset_dt + datetime.timedelta(minutes=found_key['time_window_minutes'])
            
            current_time = datetime.datetime.now()
            time_until_reset = key_expire_dt - current_time

            if time_until_reset.total_seconds() > 0:
                total_seconds_until_reset = int(time_until_reset.total_seconds())
                minutes = total_seconds_until_reset // 60
                seconds = total_seconds_until_reset % 60
                remaining_time_str = f"{minutes}m {seconds}s"
            else:
                status_message = "Expired (due for reset)"
                remaining_time_str = "Expired"
                if found_key.get('limit') is not None and found_key['limit'] != -1:
                    remaining_limit = 0
        except ValueError as e:
            app.logger.error(f"Error parsing 'last_reset' for key {api_key}: {e}. Time calculations may be inaccurate.")
            key_expire_dt = None
            remaining_time_str = "Error calculating time"
 
    response_data = {
        "verify": "true",
        "key_status": status_message,
        "key_info": {
            "remaining_limit": remaining_limit,
            "key_expire": key_expire_dt.strftime("%d-%m-%Y %H:%M:%S") if key_expire_dt else "Never",
            "remaining_time": remaining_time_str
        }
    }
    
    if status_message in ["Limit Reached", "Expired (due for reset)"]:
        response_data["verify"] = "false"
        response_data["error"] = "Key is " + status_message.lower() + ". Contact your API Provider."

    return jsonify(response_data), 200

# -------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------- #

if __name__ == '__main__':

    initial_keys = fetch_keys_from_github()
    if initial_keys:
        API_KEYS = initial_keys
        save_cached_keys(API_KEYS)
        app.logger.info("Initial API keys loaded from GitHub on startup.")
    else:
        app.logger.warning("Could not load initial API keys from GitHub. Trying local cache.")
        API_KEYS = load_cached_keys()
        if API_KEYS:
            app.logger.info("Initial API keys loaded from local cache on startup.")
        else:
            app.logger.error("No API keys found on startup. API might not function correctly.")


    app.run(debug=True, use_reloader=True, port=int(os.environ.get("PORT", 8080)))






