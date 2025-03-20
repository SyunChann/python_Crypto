from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode

# C#에서 추출한 키와 IV 값 (임의의 값으로 변경된 예제)
key = bytes([
    123, 45, 67, 89, 23, 145, 167, 34, 
    98, 111, 76, 200, 150, 120, 90, 45, 
    210, 157, 180, 133, 178, 213, 90, 67, 
    111, 143, 123, 222, 132, 56, 77, 99
])

iv = bytes([
    88, 23, 45, 67, 198, 123, 111, 200, 
    201, 54, 78, 123, 210, 157, 177, 32
])

# 암호화할 OrderId (예: "SAMPLE2411080505001")
sample_id = "SAMPLE2411080505001"

def encrypt_aes256_cbc(data, key, iv):
    # AES 암호화 설정 (CBC 모드)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # 데이터에 UTF-16 인코딩 및 PKCS7 패딩 추가
    data_bytes = data.encode("utf-16")[2:]  # UTF-16 BOM 제거
    padding_len = 16 - (len(data_bytes) % 16)
    padded_data = data_bytes + bytes([padding_len] * padding_len)
    
    # 암호화 수행
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # 암호화된 데이터를 Base64 인코딩하여 반환
    return b64encode(encrypted_data).decode()

# AES256-CBC 암호화 수행하여 EncryptionOrderId 생성
encryption_sample_id = encrypt_aes256_cbc(sample_id, key, iv)

# 결과 출력
print("암호화된 sample_id (Encryptionsample_id):", encryption_sample_id)