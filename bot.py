import asyncio
import json
import aiohttp
import logging
import os
import base64
import requests
from dataclasses import dataclass
from typing import List, Tuple, Optional

# Логирование конфигурациясы
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# GitHub конфигурациясы
@dataclass
class GitHubConfig:
    token: str
    owner: str
    repo: str
    file_path: str

def load_github_config() -> GitHubConfig:
    """GitHub конфигурациясын жүктөө."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logging.error("GITHUB_TOKEN коюлган эмес")
        raise ValueError("GITHUB_TOKEN environment variable is not set")
    logging.info("GITHUB_TOKEN ийгиликтүү жүктөлдү")
    return GitHubConfig(
        token=token,
        owner=os.getenv("GITHUB_OWNER", "taalai05"),
        repo=os.getenv("GITHUB_REPO", "Likes-api-freefire"),
        file_path=os.getenv("GITHUB_FILE_PATH", "token_bd.json")
    )

def update_github_file(config: GitHubConfig, tokens: List[dict]) -> None:
    """GitHub'та token_bd.json файлын жаңыртуу."""
    headers = {
        "Authorization": f"token {config.token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.github.com/repos/{config.owner}/{config.repo}/contents/{config.file_path}"

    try:
        # Учурдагы файлдын SHA'сын алуу
        logging.info(f"{config.file_path} үчүн SHA алуу")
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()
        current_file = response.json()
        sha = current_file.get("sha")
        if not sha:
            logging.error("GitHub жообунда SHA табылган жок")
            raise ValueError("SHA not found in GitHub response")
    except requests.RequestException as e:
        logging.error(f"SHA алууда ката кетти: {e}")
        raise

    # Контентти base64 форматына коддоо
    content_json = json.dumps(tokens, indent=2)
    encoded_content = base64.b64encode(content_json.encode()).decode()

    # Жаңыртуу үчүн payload
    payload = {
        "message": "Update token_bd.json with new tokens",
        "content": encoded_content,
        "sha": sha,
        "branch": "main"
    }

    # Файлды жаңыртуу
    try:
        logging.info(f"{config.file_path} файлын GitHub'ка жүктөө")
        response = requests.put(base_url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info("token_bd.json GitHub'та ийгиликтүү жаңыртылды")
    except requests.RequestException as e:
        logging.error(f"GitHub'ка файлды жаңыртууда ката: {e}")
        raise

# Токен генерациясы
API_URL = "http://203.18.158.202:6969/jwt?uid={uid}&password={password}"
BATCH_SIZE = 5

async def fetch_token(session: aiohttp.ClientSession, uid: str, password: str, retry_count: int = 0) -> Optional[List[str]]:
    """Берилген UID жана пароль үчүн токен алуу."""
    try:
        logging.info(f"UID үчүн токен алуу: {uid}")
        async with session.get(API_URL.format(uid=uid, password=password)) as response:
            if response.status == 200:
                data = await response.json()
                # API жообунун форматын текшерүү
                if isinstance(data, list):
                    tokens = [item.get("token") for item in data if "token" in item]
                    return tokens if tokens else None
                elif isinstance(data, dict) and "token" in data:
                    return [data["token"]]
                logging.error(f"UID үчүн күтүлбөгөн жооп форматы: {uid}")
                return None
            logging.error(f"UID үчүн токен алууда ката: {uid}. Status: {response.status}")
            return None
    except aiohttp.ClientError as e:
        if retry_count < 2:
            logging.warning(f"UID үчүн кайра аракет кылуу: {uid}. Аракет {retry_count + 1}")
            return await fetch_token(session, uid, password, retry_count + 1)
        logging.error(f"UID үчүн токен алууда ката: {uid}: {e}")
        return None

async def process_credentials_in_batches(credentials: List[Tuple[str, str]]) -> List[dict]:
    """Криденттерди партиялар менен иштетүү жана токендерди чогултуу."""
    tokens = []
    failed_credentials = []
    total_batches = (len(credentials) + BATCH_SIZE - 1) // BATCH_SIZE

    async with aiohttp.ClientSession() as session:
        for batch_index in range(total_batches):
            start_index = batch_index * BATCH_SIZE
            end_index = min(start_index + BATCH_SIZE, len(credentials))
            current_batch = credentials[start_index:end_index]

            logging.info(f"Партияны иштетүү {batch_index + 1}/{total_batches}")
            tasks = [fetch_token(session, uid, password) for uid, password in current_batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, result in enumerate(results):
                if isinstance(result, Exception):
                    logging.error(f"UID үчүн ката: {current_batch[idx][0]}: {result}")
                    failed_credentials.append(current_batch[idx])
                elif result:
                    tokens.extend({"token": token} for token in result)

        # Ийгиликсиз болгон криденттерди кайра аракет кылуу
        if failed_credentials:
            logging.info(f"{len(failed_credentials)} ийгиликсиз криденттерди кайра аракет кылуу")
            retry_tasks = [fetch_token(session, uid, password) for uid, password in failed_credentials]
            retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)

            for idx, result in enumerate(retry_results):
                if isinstance(result, Exception):
                    logging.error(f"UID кайра аракетте ийгиликсиз: {failed_credentials[idx][0]}: {result}")
                elif result:
                    tokens.extend({"token": token} for token in result)

        logging.info(f"Аяктады. Жалпы токендер: {len(tokens)}")
    return tokens

async def process_file(filename: str) -> Optional[List[dict]]:
    """Киргизүү файлын иштетүү жана токендерди генерациялоо."""
    file_path = f"{filename}.json"
    if not os.path.exists(file_path):
        logging.error(f"Файл табылган жок: {file_path}")
        return None

    logging.info(f"Файлды иштетүү: {file_path}")
    try:
        with open(file_path, "r") as file:
            data = json.load(file)  # Файлды JSON катары окуу
            if not isinstance(data, list):
                logging.error("Файлдын форматы туура эмес, тизме күтүлүүдө")
                return None

            credentials = [(str(item["uid"]), str(item["password"])) for item in data
                          if isinstance(item, dict) and "uid" in item and "password" in item]
        
        if not credentials:
            logging.error("Туура криденттер табылган жок")
            return None

        tokens = await process_credentials_in_batches(credentials)

        if tokens:
            with open("token_bd.json", "w") as f:
                json.dump(tokens, f, indent=4)
            logging.info("Токендер token_bd.json файлына сакталды")

            # GitHub'ты жаңыртуу
            try:
                config = load_github_config()
                update_github_file(config, tokens)
            except Exception as e:
                logging.error(f"GitHub'ты жаңыртууда ката: {e}")
                return None

            return tokens
        logging.error("Токендер генерацияланган жок")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"JSON файлын окууда ката: {e}")
        return None
    except Exception as e:
        logging.error(f"Файлды иштетүүдө ката: {e}")
        return None

async def main(filename: str) -> None:
    """Токендерди иштетүү жана GitHub'ты жаңыртуу үчүн негизги функция."""
    tokens = await process_file(filename)
    if not tokens:
        logging.error("Токендерди генерациялоо ийгиликсиз аяктады")
        raise SystemExit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        logging.error("Файл аты берилген жок")
        raise SystemExit(1)
    filename = sys.argv[1]
    asyncio.run(main(filename))
