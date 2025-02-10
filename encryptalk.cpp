#include <iostream>
#include <cstring>      
#include <sys/socket.h> 
#include <arpa/inet.h>  
#include <unistd.h>
#include <ncurses.h>
#include <string>
#include <thread>
#include <sstream>
#include <vector>
#include <atomic>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <algorithm>
#include <csignal>
#include <cstdlib>


#define user_num 10

const char* key_path="./cert/key.pem"; //密钥位置
const char* server_ip = "0.0.0.0";  //目标 IP
int server_port=9010; //服务器端口



int global_sock;//全局套接字
int my_id;//用户id
std::string public_key;//公钥
std::string private_key;//私钥
std::vector<std::vector<std::string>> all_message(user_num);//消息列表
int pulled[user_num];
int count[user_num];
std::atomic<int> sign =0;
int session_thread_exit_flag;
std::vector<std::string> users(user_num);//用户列表
int into_flag=0;


//套接字初始化
int tcp_init(){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("套接字创建失败");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("无效的地址");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("连接服务器失败");
        close(sock);
        return 1;
    }

    global_sock=sock;
    printf("连接服务器成功");
    return 0;
}

//base64编码
std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 不换行
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

//base64解码
std::string base64_decode(const std::string &input) {
    BIO *bio, *b64;
    char *buffer = (char *)malloc(input.size());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 不换行
    int decoded_size = BIO_read(bio, buffer, input.size());
    std::string decoded(buffer, decoded_size);
    free(buffer);
    BIO_free_all(bio);
    return decoded;
}

//加载密钥
void load_pem(){
    std::ifstream pem(key_path);
    if (!pem) {
        printf("无法打开密钥文件:%s\n",key_path);
    }else{
        std::ostringstream buffer;
        buffer << pem.rdbuf(); // 读取整个文件内容
        std::string content = buffer.str();
        std::vector<std::string> parts;
        size_t start = 0, end;
        while ((end = content.find("|||", start)) != std::string::npos) {
            parts.push_back(content.substr(start, end - start));
            start = end + 3;
        }
        parts.push_back(content.substr(start));
        my_id=std::stoi(parts[0]);
        public_key=parts[1];
        private_key=parts[2];
        //printf("加载成功 id=%d,public=%s,private%s",my_id,public_key.c_str(),private_key.c_str());
    }
}

//发送加密数据
std::string send_encrypt(const std::string& plaintext) {
    BIO* bio = BIO_new_mem_buf(public_key.c_str(), -1);

    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        printf("公钥加载失败");
    }

    int rsaLen = RSA_size(rsa);
    std::string encryptedText(rsaLen, '\0');
    int result = RSA_public_encrypt(plaintext.size(), (unsigned char*)plaintext.c_str(),(unsigned char*)encryptedText.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (result == -1) {
        throw std::runtime_error("加密失败");
    }
    
    return base64_encode(encryptedText);
}

//解密接收数据
std::string receive_decrypt(const std::string& encryptedText) {

    std::string encryptedText_decode=base64_decode(encryptedText);
    BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        throw std::runtime_error("私钥加载失败");
    }

    int rsaLen = RSA_size(rsa);
    std::string decryptedText(rsaLen, '\0');

    int result = RSA_private_decrypt(encryptedText_decode.size(), (unsigned char*)encryptedText_decode.data(),(unsigned char*)decryptedText.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (result == -1) {
        throw std::runtime_error("解密失败");
    }

    decryptedText.resize(result); // 去掉填充
    return decryptedText;
}

// (发送数据，to_who，操作类型),实际上发送的报文包含了自己的id
int sendto(char* message ,int id,int type) {
    // 获取消息的实际长度
    size_t message_length = strlen(message);
    char header[3];
    sprintf(header, "%02d",my_id);
    std::string encrypt_buffer(header);

    // 分配足够的缓冲区，预留 10 字节用于 ID 和其他数据
    char* buffer = (char*)malloc(message_length + 10);
    snprintf(buffer, message_length + 10, "%d%02d:%s", type, id, message);
    encrypt_buffer+=send_encrypt(buffer);
    // printf("%s",message);
    if (send(global_sock, encrypt_buffer.c_str(), strlen(encrypt_buffer.c_str()), 0) == -1) {
        perror("发送失败");
    } else {
        //std::cout << "Message sent to " << server_ip << ":" << port << std::endl;
    }
    return 0;
}

//打印帮助
void print_help() {
    std::cout << "指令：\n"
              << "  list                 - 列出用户\n"
              << "  to {username}/{id}   - 发送消息给其他用户\n"
              << "  connect              - 尝试重新连接服务器\n"
              << "  chname {newname}     - 修改用户名称\n"
              << "  exit                 - 退出\n"
              << "  help                 - 显示这条帮助\n";
}

//请求用户信息
void pull_user(){
    sendto("",00,1);
}

//请求聊天记录
std::vector<std::string> pull_message(int to_id){
    //从服务器中接受数据,把数据处理成为字符串存入vector
    sendto("",to_id,2);
    return all_message[to_id];
}

//字符编码转换
std::wstring utf8_to_wstring(std::string utf8_str) {
    // 确定转换后需要的宽字符数（不包括终止符）
    size_t len = std::mbstowcs(nullptr, utf8_str.c_str(), 0);
    if (len == static_cast<size_t>(-1)) {
        return L"";
    }
    // 分配足够的缓冲区
    std::vector<wchar_t> buffer(len + 1);
    std::mbstowcs(buffer.data(), utf8_str.c_str(), buffer.size());
    return std::wstring(buffer.data());
}

//刷新消息框线程
void refresh_msg_pad(WINDOW* msg_pad, int id, std::atomic<int> &pad_pos, int max_x, int max_y) {
    while(true) {
        if(sign) {
            // 当有新消息时，循环输出所有未显示的消息
            while (all_message[id].size() > (count[id]-1)) {
                std::wstring wmsg = utf8_to_wstring(all_message[id][count[id]-1]);
                mvwaddwstr(msg_pad, count[id]+1, 0, wmsg.c_str());
                count[id]++;
                //wprintw(msg_pad, "%s", all_message[id][count[id]].c_str());
                // if(pad_pos<(max_x-1)){
                if(count[id]>(max_y-1)){
                    pad_pos=count[id]-max_y+2;
                }
                prefresh(msg_pad, pad_pos, 0, 0, 0, max_y - 2, max_x - 1);
                // }
            }
            sign = 0;
        }
        if(session_thread_exit_flag) {
            break;
        }
    }
}

//进入聊天会话
void into_session(int id) {
    setlocale(LC_ALL, ""); 
    initscr();
    cbreak();
    noecho();

    int max_y, max_x;
    count[id] = 0;
    session_thread_exit_flag = 0;

    getmaxyx(stdscr, max_y, max_x);

    int pad_lines = 100;
    int pad_cols = max_x;
    WINDOW* msg_pad = newpad(pad_lines, pad_cols);
    if (!msg_pad) {
        endwin();
        fprintf(stderr, "无法创建聊天框\n");
        exit(1);
    }
    scrollok(msg_pad, TRUE);

    WINDOW* input_win = newwin(1, max_x, max_y - 1, 0);
    keypad(input_win, TRUE);

    std::string msg_pad_header = "=== to " + users[id] + " ===   回车发送消息，exit返回\n";
    std::wstring wmsg_pad_header = utf8_to_wstring(msg_pad_header);
    mvwaddwstr(msg_pad, 0, 0, wmsg_pad_header.c_str());
    count[id]++;
    //wprintw(msg_pad, "%s",msg_pad_header.c_str());
    

    // 如果尚未拉取消息，则调用拉取函数
    if(pulled[id]) {
        sign = 1;
    } else {
        pull_message(id);
        pulled[id] = 1;
    }

    std::atomic<int> pad_pos = 0;  // 当前滚动位置
    prefresh(msg_pad, pad_pos, 0, 0, 0, max_y - 2, max_x - 1);
    // 启动刷新消息窗口的线程
    std::thread msg_thread(refresh_msg_pad, msg_pad, id, std::ref(pad_pos), max_x, max_y);
    msg_thread.detach();

    wchar_t input[100] = L"";
    int index = 0;
    wint_t ch;

    while (true) {
        werase(input_win);
        mvwaddwstr(input_win, 0, 0, L"> ");
        mvwaddwstr(input_win, 0, 2, input);  // 宽字符打印
        wrefresh(input_win);

        wget_wch(input_win, &ch);
        if (ch == L'\n') {  // 回车键
            time_t now = time(NULL);
            struct tm *tm_struct = localtime(&now);

            //获取当前时间
            char time_str[20];
            strftime(time_str, sizeof(time_str), "%m.%d %H:%M", tm_struct);

            // 拼接消息字符串
            std::stringstream ss;
            char tranfer[100];
            std::wcstombs(tranfer, input, sizeof(tranfer));
            ss << "[" << time_str << "] " << users[my_id] << " : " << tranfer << "\n";
            std::string msg_str = ss.str();
            if (wcscmp(input, L"exit") == 0) {
                break;
            }

            // 直接在消息窗口显示，然后发往服务器
            std::wstring wmsg = utf8_to_wstring(msg_str);
            mvwaddwstr(msg_pad, count[id]+1, 0, wmsg.c_str());
            //wprintw(msg_pad, "%s",msg_str.c_str());
            count[id]++;
            if(count[id]>(max_y-1)){
                pad_pos=count[id]-max_y+2;
            }
            prefresh(msg_pad, pad_pos, 0, 0, 0, max_y - 2, max_x - 1);

            // 保存消息到消息队列
            all_message[id].push_back(msg_str);
            sendto(tranfer, id, 0);
            memset(input, 0, sizeof(input));
            index = 0;
        }
        else if (ch == KEY_UP) {  // 上方向键滚动
            if (pad_pos > 0)
                pad_pos--;
        }
        else if (ch == KEY_DOWN) {  // 下方向键滚动
            if (pad_pos < pad_lines - (max_y - 1))
                pad_pos++;
        }
        else if (ch == KEY_BACKSPACE || ch == 127) {  // 退格键
            if (index > 0) {
                input[--index] = L'\0';
            }
        } 
        else if (index < static_cast<int>(sizeof(input)) - 1) {
            input[index++] = ch;
            input[index] = L'\0';
        }
        prefresh(msg_pad, pad_pos, 0, 0, 0, max_y - 2, max_x - 1);
    }

    session_thread_exit_flag = 1;//退出会话，线程终止符
    delwin(input_win);
    delwin(msg_pad);
    endwin();
}

bool is_number(const std::string& str) {
    if (str.empty()) return false;
    for (char c : str) {
        if (!isdigit(c)) return false;
    }
    return true;
}

//从users中映射名字到id
int find_id(const std::string& target) {
    auto it = std::find(users.begin(), users.end(), target);
    if (it != users.end()) {
        return std::distance(users.begin(), it);  // 计算索引
    }
    return 0;  // 未找到返回 -1
}

//处理输入命令
int handle(std::string input){
    std::string args;
    if (input == "exit") {
        std::cout << "Exiting..." << std::endl;
        close(global_sock);
        return 0;
    } else if (input == "help") {
        print_help();
    }else if (input=="pull"){
        pull_user();
    }else if (input=="list"){
        for (size_t i = 0; i < users.size(); ++i) {
            if(!users[i].empty()){
                std::cout << users[i] << ", ID: " << i << std::endl;
            }
        }
    } else if(input == "connect") {
        tcp_init();
    } else if (input.rfind("to ",0) == 0){
        args = input.substr(3);
        if(is_number(args)){
            if(std::stoi(args)>=user_num){
                printf("无效的id");
            }else{
                into_session(std::stoi(args));
            }
        }else{
            into_session(find_id(args));
        }
    } else if (input.rfind("chname ")==0){
        args = input.substr(7);
        sendto(const_cast<char*>(args.c_str()),00,3);
    } else {
        std::cout << "Unknown command. Type 'help' for commands.\n";
    }
    return 1;
}

//用户心跳
void alive(){
    std::thread([](){
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        sendto("", 0, 4);
    }
    }).detach();
}

//用户上线
void user_on(){
    sendto("",0,5);
    alive();
}

//处理接受的消息
void handle_received_message(std::string data){
    std::stringstream ss(data);
    char type_char;
    std::string id_str(2,'0');
    int type,received_id;
    // printf("from handle func:%s",data.c_str());
    

    ss.get(type_char); // 读取第一个字符
    type = type_char - '0'; // 转换为整数
    if(type==0){
        ss.get(id_str[0]);          
        ss.get(id_str[1]);
        received_id = std::stoi(id_str);
        std::string part, time, id, message;

        while (std::getline(ss, part, '}')) {  // 按 } 分割多个消息
            if (part.empty() || part[0] != '{') continue;  // 过滤无效内容
            part = part.substr(1);  // 去掉{

            std::stringstream msg_ss(part);
            std::getline(msg_ss, time, '|');
            std::getline(msg_ss, id, '|');
            std::getline(msg_ss, message);


            std::string formatted_message = "[" + time + "] " + users[std::stoi(id)] + " : " + message+"\n";
            // printf("from format:%s",formatted_message.c_str());
            all_message[received_id].push_back(formatted_message);
        }
        // for (const std::string& msg : all_message[2]) {
        //         printf("%s",msg.c_str());
        //     }
        sign=1;
    }else if (type==1){
        std::string part,id,name;
        while (std::getline(ss, part, '}')) {
            if (part.empty() || part[0] != '{') continue; 
            part = part.substr(1);
            std::stringstream msg_ss(part);
            std::getline(msg_ss, id, '|');
            std::getline(msg_ss, name);
            users[std::stoi(id)]=name;
        }
        into_flag=1;
    }
}

//监听线程
void listening(){
    std::string data;
    char buffer[1024];  // 存储接收的数据
    memset(buffer, 0, sizeof(buffer));  // 清空缓冲区
    while (true) {//从缓冲区中读取完整报文
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(global_sock, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            data += buffer;

            // 判断是否接收到完整报文（以 "|exit}" 结尾）
            size_t pos;
            while ((pos = data.find("|exit}")) != std::string::npos) {
                std::string message = data.substr(0, pos);
                data.erase(0, pos + 6);  // 移除已处理的部分

                // 解密处理消息
                message = receive_decrypt(message);
                handle_received_message(message);
            }
        } else if (bytes_received == 0) {
            std::cout << "连接丢失" << std::endl;
            break;
        } else {
            std::cerr << "接收失败" << std::endl;
            break;
        }
    }
}

void listen_from_server(){
    std::thread listen_thread(listening);
    listen_thread.detach(); // 让线程独立运行，不阻塞主线程
}

void print_banner(){
    std::cout << R"(                                                                        
                                              ,--------.       ,--.,--.     
     ,---. ,--,--,  ,---.,--.--.,--. ,--.,---.'--.  .--',--,--.|  ||  |,-.  
    | .-. :|      \| .--'|  .--' \  '  /| .-. |  |  |  ' ,-.  ||  ||     /  
    \   --.|  ||  |\ `--.|  |     \   ' | '-' '  |  |  \ '-'  ||  ||  \  \  
     `----'`--''--' `---'`--'   .-'  /  |  |-'   `--'   `--`--'`--'`--'`--' 
                                `---'   `--'                                
    )" << std::endl;
}

int into(){
    if(users[my_id].empty()){
        printf("验证失败\n");
    }else{
        printf("验证：%s  ",users[my_id].c_str());
        printf("输入 help 指令以展示帮助信息\n");
        return 1;
    }
    return 0;
}

void handle_sigint(int sig) {
    close(global_sock);
    std::system("stty sane");
    exit(0);
}

int main(){
    std::string input;                 
    std::string username;
    load_pem();//加载证书
    tcp_init();//初始化套接字
    user_on();//用户上线
    listen_from_server();//监听连接
    pull_user();//拉取用户
    print_banner();//打印banner
    signal(SIGINT, handle_sigint);
    while(true){
        if(into_flag){
            into();
            break;
        }
    }
    while (true) {
        std::cout << "> ";  // 显示提示符
        if (!std::getline(std::cin, input)) {  
        break;  //处理EOF或输入错误
        }

        if (!input.empty() && input.back() == '\r') {
            input.pop_back();  
        }

        if (handle(input) == 0) {
            break; //退出循环
        }
    }
}