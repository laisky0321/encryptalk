from Crypto.PublicKey import RSA
import os
import mysql.connector
import configparser

# 生成 2048 位 RSA 密钥对
key_client = RSA.generate(2048)
key_server = RSA.generate(2048)

id=input("请输入两位数id:")

os.makedirs(f"./cert/{id}/", exist_ok=True)

with open(f"./cert/{id}/client_public.pem", "wb") as f:
    f.write(key_client.publickey().export_key())

with open(f"./cert/{id}/server_private.pem", "wb") as f:
    f.write(key_server.export_key())

if os.path.exists(f"./cert/{id}/key.pem"):
    os.remove(f"./cert/{id}/key.pem")
with open(f"./cert/{id}/key.pem", "ab") as f:
    f.write((id+"\n").encode())
    f.write("|||\n".encode())
    f.write(key_server.publickey().export_key())
    f.write("\n|||\n".encode())
    f.write(key_client.export_key())

print("密钥已生成并保存！")

config = configparser.ConfigParser()
config.read("config.ini")
sql_host=config["mysql"]["host"]
sql_port=int(config["mysql"]["port"])
sql_database=config["mysql"]["database"]
sql_user=config["mysql"]["user"]
sql_password=config["mysql"]["password"]
print("数据库配置加载成功")

name=input("输入用户名：")
conn=mysql.connector.connect(host=sql_host,port=sql_port, user=sql_user, password=sql_password, database=sql_database,ssl_disabled=True)
cursor = conn.cursor()
cursor.execute("INSERT INTO users (id,user) VALUES (%s, %s)", (int(id),name))
conn.commit()
conn.close()
print("用户信息已添加至数据库")


