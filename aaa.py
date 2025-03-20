from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import requests
import random
import string

# 더미 데이터 (랜덤 값 생성)
def generate_random_string(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_hex(length=64):
    return ''.join(random.choices('0123456789abcdef', k=length))

# API 키와 Client ID (난수 값으로 변경)
client_id = b64encode(generate_random_string(16).encode()).decode()  
api_key = generate_random_hex(64)

# 고정된 암호화 키와 IV (난수 값으로 변경)
encryption_key = b64encode(generate_random_string(32).encode()).decode()
initialisation_vector = generate_random_string(16).encode("utf-8")

# 암호화할 OrderId (랜덤 주문번호)
order_id = f"E{random.randint(1000000000, 9999999999)}"

def encrypt_aes256_cbc(data, key, iv):
    # AES 암호화 설정 (CBC 모드)
    cipher = Cipher(algorithms.AES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 데이터에 PKCS7 패딩 추가 (PKCS5와 동일)
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    
    # 암호화 수행
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # 암호화된 데이터를 Base64 인코딩하여 반환
    return b64encode(encrypted_data).decode().rstrip("=")

# 1. OrderId를 먼저 Base64 인코딩
base64_encoded_order_id = b64encode(order_id.encode("utf-8")).decode("utf-8")

# 2. AES256-CBC 암호화 수행하여 EncryptionOrderId 생성
encryption_order_id = encrypt_aes256_cbc(base64_encoded_order_id.encode("utf-8"), encryption_key, initialisation_vector)

# 3. 암호화된 결과를 URL에 추가
api_url = f"https://wapi.example.com/api/v1/order/{encryption_order_id}"  # API URL을 예제로 변경

# 헤더 설정
headers = {
    "ClientID": client_id,
    "ApiKey": api_key
}

# API 요청 전송 (더미 URL이므로 실제 요청 X)
response = requests.get(api_url, headers=headers)

# 응답 출력
print("Base64 인코딩된 OrderId:", base64_encoded_order_id)
print("암호화된 OrderId (EncryptionOrderId):", encryption_order_id)
print("API 호출 URL:", api_url)
print("응답 상태 코드:", response.status_code)
print("응답 본문:", response.text)
