# 🔐 Python Crypto Project

이 프로젝트는 **AES-256 CBC 암호화**를 사용하여 특정 데이터를 암호화하고,  
외부 API와 연동하는 기능을 구현합니다.  

`aaa.py`와 `bbb.py` 두 개의 주요 스크립트가 포함되어 있습니다.

---

## 📌 주요 파일 설명

### **1️⃣ `aaa.py`**
- 특정 `OrderId` 값을 AES-256 CBC 방식으로 암호화하여 API 호출을 수행합니다.
- API 키 및 Client ID를 사용하여 인증합니다.
- 대외비 데이터를 보호하기 위해 난수 기반의 더미 데이터를 생성할 수 있습니다.

🔹 **주요 기능**
✅ `OrderId`를 **Base64 인코딩 후 AES-256 CBC 암호화**  
✅ API 요청을 위해 암호화된 값을 URL에 포함  
✅ `requests` 모듈을 사용하여 **API 호출 및 응답 처리**

---

### **2️⃣ `bbb.py`**
- 특정 문자열을 AES-256 CBC 방식으로 암호화하는 스크립트입니다.
- `aaa.py`와 유사하지만, API 연동 없이 단순한 암호화 테스트 용도로 사용됩니다.

🔹 **주요 기능**
✅ 랜덤 **AES-256 CBC 암호화 키와 IV** 생성  
✅ 임의의 `sample_id`를 암호화하여 결과 출력  

---

## 🚀 실행 방법

### **1️⃣ Python 환경 설정**
Python이 설치되어 있는지 확인합니다.

```sh
python --version


2️⃣ 필요한 패키지 설치 및 실행방법
pip install cryptography requests
python aaa.py
python bbb.py
