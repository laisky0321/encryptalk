import socket
import mysql.connector
import threading
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import configparser

USER_NUM=10
HOST = '0.0.0.0'  # 本地地址
PORT = 9010       # 监听端口


sql_host=""
sql_user=""
sql_password=""
sql_database=""
sql_port=0


online_user={}#以字符串为索引
timer={}
beat={}
user_socket={}#以字符串为索引
public_key={}
private_key={}


# 从文件加载公钥
def load_public_key(filename):
    with open(filename, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

# 从文件加载私钥
def load_private_key(filename):
    with open(filename, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

# RSA 加密,id为字符串格式
def send_encrypt(id,message):
    cipher = PKCS1_OAEP.new(public_key[id])
    encrypted_data = cipher.encrypt(message.encode())
    msg=base64.b64encode(encrypted_data).decode()+"|exit}"
    user_socket[id].sendall(msg.encode())

# RSA 解密
def receive_decrypt(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_data.decode()

def load_config():
    global sql_host, sql_port, sql_database, sql_user, sql_password
    config = configparser.ConfigParser()
    config.read("config.ini")
    sql_host=config["mysql"]["host"]
    sql_port=int(config["mysql"]["port"])
    sql_database=config["mysql"]["database"]
    sql_user=config["mysql"]["user"]
    sql_password=config["mysql"]["password"]
    print("数据库配置加载成功")

def mysql_conn():
    print(f"Host: {sql_host}, Port: {sql_port}")
    return mysql.connector.connect(host=sql_host,port=sql_port, user=sql_user, password=sql_password, database=sql_database,ssl_disabled=True)


def save_message(id,to_id,message):
    if online_user.get(to_id,0)!=0:
        client_data=f"0{id}"
        client_data+="{%s|%s|%s}"%(datetime.now().strftime("%m.%d %H:%M"),id,message)
        send_encrypt(to_id,client_data)
        print(f"转发消息{client_data}给{to_id}")
        # 连接 MySQL 数据库
    print("正在保存消息")
    conn = mysql_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (from_id, to_id, message) VALUES (%s, %s, %s)", (int(id), int(to_id), message))
    conn.commit()
    conn.close()
    print("消息已保存")
    return 0


#list（user）
def pull_user(id):
    conn = mysql_conn()
    cursor = conn.cursor()
    cursor.execute("select id,user from users")
    client_data="1"
    result=cursor.fetchall()
    conn.close()
    print(f"拉取的信息为")
    for info in result:
        client_data+="{%s|%s}"%(f"{info[0]:02d}",info[1])
    print(client_data)
    send_encrypt(id,client_data)
    return 0

#list（time,from_id,message）
def pull_message(from_id,to_id):
    conn = mysql_conn()
    cursor = conn.cursor()
    cursor.execute("select time,from_id,message from messages where (from_id=%s and to_id=%s) or (from_id=%s and to_id=%s)",(from_id,to_id,to_id,from_id))
    result=cursor.fetchall()
    print(result)
    conn.close()
    for msg in result:
        client_data=f"0{to_id}"#0代表是消息
        print("进入循环")
        client_data+="{%s|%s|%s}"%(msg[0].strftime("%m.%d %H:%M"),msg[1],msg[2])
        print(client_data)
        send_encrypt(from_id,client_data)
        print(f"发送消息{client_data}给{from_id}")

    return 0

def chuser_info(id,info):
    conn = mysql_conn()
    cursor = conn.cursor()
    cursor.execute("update users set user=%s where id =%s",(info,id))
    conn.commit()
    conn.close()
    for key in [k for k, v in online_user.items() if v == 1]:  
        pull_user(key)
    return 0

#输入是是否执行这个函数，输出是一个字典
#每5分钟清除在线标记
def alive(id):
    beat[id]=1
    return 0

#用户的在线情况每5分钟清零
def reset_online(id):
    if beat[id]!=1:
        online_user[id]=0#没有心跳则用户下线
    else:#有心跳则继续计时
        beat[id]=0
        timer[id] = threading.Timer(300, reset_online, args=(id,)).start()


def user_on(id,client_scoket):
    online_user[id]=1
    alive(id)
    reset_online(id)
    user_socket[id]=client_scoket
    send_encrypt(id,"")
    return 0

def handle(data,client_socket):
    header, content= data.split(":")
    id=header[:2]
    operation=header[2]
    to_id=header[3:5]
    print(f"recived id={id}, operation=={operation}, to_id={to_id}, message={content}")

    if operation=='0':
        #发送消息
        print("准备保存消息")
        return save_message(id,to_id,content)
    elif operation=='1':
        #拉取用户
        print("准备拉取用户")
        return pull_user(id)
    elif operation=='2':
        #拉取消息
        return pull_message(id,to_id)
    elif operation=='3':
        #修改用户名
        return chuser_info(id,content)
    elif operation=='4':
        #用户在线心跳
        return alive(id)
    elif operation=="5":
        #用户上线
        return user_on(id,client_socket)
    else:
        print("没有执行任何指令")


def handle_client(client_socket, client_address):
    print(f"Connection from {client_address}")
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break  # 客户端断开连接
            print(f"Received message from {client_address}: {data}")
            client_id=data.decode('utf-8')[:2]
            encrypt_data=data.decode('utf-8')[2:]
            public_key[client_id]=load_public_key(f"./cert/{client_id}/client_public.pem")
            private_key[client_id]=load_private_key(f"./cert/{client_id}/server_private.pem")
            decrypt_data=client_id+receive_decrypt(encrypt_data,private_key[client_id])
            handle(decrypt_data,client_socket)
    except Exception as e:
        print(f"Error with {client_address}: {e}")


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(USER_NUM)

    print(f"Server listening on {HOST}:{PORT}...")
    load_config()

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()  # 启动线程

if __name__ == "__main__":
    main()








