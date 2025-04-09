from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def aes_encrypt(key, ptext):
    # 確保金鑰長度為 16、24 或 32 位元組（AES-128、192、256）
    key = key.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        raise ValueError("金鑰長度必須為16、24或32字節")

    # 生成IV
    iv = os.urandom(16) 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 填充
    ptext_bytes = ptext.encode('utf-8')
    pad_data = pad(ptext_bytes, AES.block_size)
    
    # 加密
    ctext = cipher.encrypt(pad_data)
    return iv + ctext  # 回傳 IV + 密文串接結果

def aes_decrypt(key, encrypted):
    # 確保金鑰長度為 16、24 或 32 位元組
    key = key.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        raise ValueError("金鑰長度必須為16、24或32字節")
    
    # 提取 IV 和密文
    iv = encrypted[:16]
    ctext = encrypted[16:]
    
    # 解密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_data = cipher.decrypt(ctext)
    return unpad(pad_data, AES.block_size).decode('utf-8')

try:
    key = input("輸入金鑰 (長度必須為16、24或32字節): ")
    ptext = input("輸入待加密字串: ")

    # 加密
    encrypted = aes_encrypt(key, ptext)
    print(f"加密後密文: {encrypted.hex()}")

    # 解密
    decrypted = aes_decrypt(key, encrypted)
    print(f"解密後字串: {decrypted}")

    # 驗證
    if decrypted == ptext:
        print("驗證成功")
    else:
        print("驗證失敗")

except ValueError as e:
    print(f"錯誤: {e}")
except Exception as e:
    print(f"發生錯誤: {e}")
