# Encryptalk

Encryptalk 是一款在 Linux 上运行的基于非对称加密的命令行聊天程序，采用 OpenSSL 进行消息加密，支持用户身份验证与安全通信。


## 安装与使用

### 客户端安装
1. **编译**
   在编译之前，请在代码开头填入服务器信息。
   ```bash
   g++ encryptalk.cpp -o encryptalk -lssl -lcrypto -lncursesw
   ```
2. **放置密钥**
   将服务器分发的 `key.pem` 放入可执行文件所在目录下的`cert` 目录：
   ```bash
   mkdir -p cert
   mv key.pem cert/
   ```
3. **运行客户端**
   ```bash
   ./encryptalk
   ```
    ![image](https://github.com/user-attachments/assets/8f8128e6-a1e1-4e16-a1db-fadee48e1307)
4. **使用示例**
   发送消息给某个用户：
   ```
   to username/id
   ```
   ![image](https://github.com/user-attachments/assets/83849eab-cdf1-4fc2-8c89-69261ea6e123)
   ![image](https://github.com/user-attachments/assets/539a711f-786e-494f-b3ce-786a7c18973f)
  

### 服务端安装
1. **创建数据库**
   ```sql
   CREATE DATABASE encryptalk;
   USE encryptalk;
   CREATE TABLE messages (
       time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       from_id BIGINT NOT NULL,
       to_id BIGINT NOT NULL,
       message TEXT NOT NULL
   );
   CREATE TABLE users (
       id INT NOT NULL PRIMARY KEY,
       user VARCHAR(20) NOT NULL
   );
   ```
2. **修改配置文件**
   在 `config.ini` 填写数据库连接信息。

3. **生成密钥 & 注册用户**
   运行 `generate.py`，按照提示输入两位数字 ID（如 `01`），然后输入用户名。
   ```bash
   python generate.py
   ```
   成功后，将在当前目录生成 `cert` 目录，包含用户 ID 目录。
   *请将 用户ID目录下的`key.pem` 发送给客户端。*

4. **启动服务器**
   ```bash
   python server.py
   ```


