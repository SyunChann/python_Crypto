# 🔐 Python Crypto Project

이 프로젝트는 **AES-256 CBC 암호화**를 사용하여 특정 데이터를 암호화하고,  
외부 API와 연동하는 기능을 구현합니다.

하지만 **C#과 Python에서 동일한 알고리즘을 사용해도 암호화 결과가 달랐던 문제**가 있었습니다.  
이를 해결하기 위해 **C#의 `PasswordDeriveBytes` 방식과 동일한 키/IV를 추출**하는 방법을 찾았습니다.

---

## 🛠 **문제 확인 및 해결 과정**

### ✅ **문제 확인**
1. **같은 암호화 알고리즘을 사용해도 결과가 다름**  
   - Python과 C#에서 같은 AES-256 CBC 암호화를 적용했음에도 결과가 일치하지 않음.  
   - `Base64`, `Btoa`, `AES`, `SHA` 등 **인코딩/해싱 순서를 맞춰도 동일한 값이 나오지 않음**.  

2. **Python에서 C#의 `PasswordDeriveBytes`와 동일한 키, IV를 생성하지 못함**  
   - Python의 `PBKDF2HMAC` 등을 사용해 C#과 동일한 키/IV를 생성하려 했지만 미묘한 차이 발생.
   - 내부적으로 **Salt, 반복 횟수 및 키 스트레칭 방식 차이**가 존재하여 완전히 동일한 결과를 얻지 못함.

---

### ✅ **문제 해결**
🔹 **C#에서 `PasswordDeriveBytes`로 생성된 정확한 키와 IV를 직접 추출하여 Python 코드에 하드코딩함**  
🔹 **Python에서 동일한 키와 IV를 사용하면, 암호화 결과가 완벽히 일치함을 확인**  

📌 **참고 블로그:**  
🔗 출처: [https://code-soo.tistory.com/47](https://code-soo.tistory.com/47)  
_(Code_Sootorage 블로그에서 PasswordDeriveBytes와 PBKDF2HMAC 차이를 상세히 설명)_

---

## 📌 주요 파일 설명

### **1️⃣ `aaa.py`**
- 특정 `OrderId` 값을 **AES-256 CBC 방식**으로 암호화하여 API 호출을 수행하는 스크립트.
- API 키 및 Client ID를 사용하여 인증.
- C#과 동일한 키/IV를 사용하도록 조정하여 정확한 암호화 결과를 도출.

🔹 **주요 기능**
✅ `OrderId`를 **Base64 인코딩 후 AES-256 CBC 암호화**  
✅ C# `PasswordDeriveBytes` 방식과 동일한 키/IV 사용  
✅ API 요청을 위해 암호화된 값을 URL에 포함  
✅ `requests` 모듈을 사용하여 **API 호출 및 응답 처리**

---

### **2️⃣ `bbb.py`**
- 특정 문자열을 **AES-256 CBC 방식**으로 암호화하는 테스트 스크립트.
- `aaa.py`와 유사하지만, API 연동 없이 단순한 암호화 테스트 용도로 사용됨.
- **C# `PasswordDeriveBytes` 방식과 동일한 키/IV를 사용하여 정확한 암호화 결과를 도출**.

🔹 **주요 기능**
✅ 랜덤 **AES-256 CBC 암호화 키와 IV** 생성  
✅ C# `PasswordDeriveBytes`와 동일한 방식 적용  
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
