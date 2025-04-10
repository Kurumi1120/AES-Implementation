# AES-Implementation
此程式使用Python語言，演示基於PyCryptodome的AES加密演算法實作，並對加密結果進行解密驗證。

# 功能介紹
- **加密**：
  - 使用 AES-CBC 模式。
  - 可使用 128、192 或 256 位元金鑰（16、24 或 32 字節）。
  - 生成隨機 IV（初始化向量）。
  - 填充明文至 16 字節塊。
- **解密**：
  - 從密文中提取 IV 並解密。
  - 移除填充，恢復原始字串。
- **錯誤處理**：
  - 驗證金鑰長度。
  - 進行解密驗證，檢查解密結果與原始明文是否一致。

# 需求
- **Python 3.7+**

# 函式庫需求
- **pycryptodome**

