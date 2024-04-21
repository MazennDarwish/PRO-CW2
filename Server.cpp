#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace std;

// Constants
#define BUFFER_LEN 1024
#define NAME_LEN 20
#define MAX_CLIENT_NUM 32
#define CREDENTIALS_FILE "credentials.txt"
#define MAX_MESSAGE_LEN 1024
#define MAX_MESSAGES 100

// Mutexes and condition variables for thread synchronization
mutex num_mutex;
mutex port_mutex;
thread chat_thread[MAX_CLIENT_NUM];
thread send_thread[MAX_CLIENT_NUM];

int current_client_num = 0;
int users_per_port[MAX_CLIENT_NUM] = {0};

//Struct for message queue
struct MessageQueue {
    string messages[MAX_MESSAGES];
    int front;
    int rear;
    mutex queue_mutex;
    condition_variable cv;

    MessageQueue() : front(0), rear(0) {}

    //Push message into the queue
    void push(const string& message) {
        unique_lock<mutex> lock(queue_mutex);
        messages[rear] = message;
        rear = (rear + 1) % MAX_MESSAGES;
        cv.notify_one();
    }

    // Pop message from the queue
    string pop() {
        unique_lock<mutex> lock(queue_mutex);
        while (front == rear) {
            cv.wait(lock);
        }
        string message = messages[front];
        front = (front + 1) % MAX_MESSAGES;
        return message;
    }
};

// Struct for client data
struct Client {
    int valid;
    int fd_id;
    int socket;
    char name[NAME_LEN + 1];
    MessageQueue message_q;

    Client() : valid(0), fd_id(0), socket(0) {
        memset(name, 0, sizeof(name));
    }
} client[MAX_CLIENT_NUM];

mutex client_mutex[MAX_CLIENT_NUM];
condition_variable client_cv[MAX_CLIENT_NUM];

// Function prototypes
void chat(Client *data);
void handle_send(Client *data);
void handle_recv(Client *data);
bool userExists(const string &username);
bool validateUser(const string &username, const string &password);
bool addUser(const string &username, const string &password);
void serverSetup(int server_port);
string caesarEncrypt(string text, int shift);
string caesarDecrypt(string text, int shift);

// Main function
int main() {
    int choice;
    while (true) {
        cout << "1. Sign up\n2. Log in\n3. Exit\nEnter your choice: ";
        cin >> choice;

        if (choice == 1) {
            string username, password;
            cout << "Enter username: ";
            cin >> username;
            cout << "Enter password: ";
            cin >> password;

            if (addUser(username, password)) {
                cout << "User signed up successfully.\n";

                int loginChoice;
                cout << "Do you want to log in now? (1 for Yes, 0 for No): ";
                cin >> loginChoice;

                if (loginChoice == 1) {
                    cout << "Logging in...\n";
                    cout << "Enter username: ";
                    cin >> username;
                    cout << "Enter password: ";
                    cin >> password;
                    if (validateUser(username, password)) {
                        int server_port;
                        cout << "Please enter the port number of the server: ";
                        cin >> server_port;
                        serverSetup(server_port);
                    } else {
                        cout << "Invalid username or password.\n";
                        return 1;
                    }
                }
            } else {
                cout << "Failed to sign up user.\n";
            }
        } else if (choice == 2) {
            string username, password;
            cout << "Enter username: ";
            cin >> username;
            cout << "Enter password: ";
            cin >> password;

            if (!validateUser(username, password)) {
                cout << "Invalid username or password.\n";
                return 1;
            }

            int server_port;
            cout << "Please enter the port number of the server: ";
            cin >> server_port;

            serverSetup(server_port);
        } else if (choice == 3) {
            return 0;
        } else {
            cout << "Invalid choice.\n";
        }
    }
    return 0;
}

// Setup the server
void serverSetup(int server_port) {
    int server_sock;
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(server_port);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, MAX_CLIENT_NUM + 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server started successfully!\n");
    printf("You can join the chatroom by connecting to 127.0.0.1:%d\n\n", server_port);

     // Accept incoming connections
    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock == -1) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        port_mutex.lock();
        int port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
        port_mutex.unlock();

        num_mutex.lock();
        if (users_per_port[port] >= 2) {
            num_mutex.unlock(); // Release the mutex before sending the error message
            if (send(client_sock, "ERROR: Port capacity reached", strlen("ERROR: Port capacity reached"), 0) < 0)
                perror("send");
            shutdown(client_sock, 2);
            continue;
        } else {
            users_per_port[port]++; // Increment the count of users on this port
        }
        num_mutex.unlock();

        if (current_client_num >= MAX_CLIENT_NUM) {
            if (send(client_sock, "ERROR", strlen("ERROR"), 0) < 0)
                perror("send");
            shutdown(client_sock, 2);
            continue;
        } else {
            if (send(client_sock, "OK", strlen("OK"), 0) < 0)
                perror("send");
        }

        // Receive username from client
        char name[NAME_LEN + 1] = {0};
        ssize_t state = recv(client_sock, name, NAME_LEN, 0);
        if (state < 0) {
            perror("recv");
            shutdown(client_sock, 2);
            continue;
        } else if (state == 0) {
            shutdown(client_sock, 2);
            continue;
        }

        // Add client to the chatroom
        for (int i = 0; i < MAX_CLIENT_NUM; i++) {
            if (!client[i].valid) {
                num_mutex.lock();
                memset(client[i].name, 0, sizeof(client[i].name));
                strcpy(client[i].name, name);
                client[i].valid = 1;
                client[i].fd_id = i;
                client[i].socket = client_sock;

                num_mutex.unlock();

                chat_thread[i] = thread(chat, &client[i]);
                printf("%s joined the chatroom. Online Users : %d\n", client[i].name, ++current_client_num);

                break;
            }
        }
    }

    // Close all sockets and exit
    for (int i = 0; i < MAX_CLIENT_NUM; i++)
        if (client[i].valid)
            shutdown(client[i].socket, 2);
    shutdown(server_sock, 2);
    exit(EXIT_SUCCESS);
}

// Chat function
void chat(Client *data) {
    // Welcome message
    char hello[100];
    sprintf(hello, "Hello %s, Welcome to the chatroom. Current online Users: %d\n", data->name, current_client_num);
    data->message_q.push(hello);

    memset(hello, 0, sizeof(hello));
    sprintf(hello, "New User %s joined! Online Users: %d\n", data->name, current_client_num);
    for (int j = 0; j < MAX_CLIENT_NUM; j++) {
        if (client[j].valid && client[j].socket != data->socket) {
            client[j].message_q.push(hello);
        }
    }

// Start the send thread
    send_thread[data->fd_id] = thread(handle_send, data);

    // Handle receiving messages
    handle_recv(data);

    // Remove client from chatroom
    num_mutex.lock();
    data->valid = 0;
    --current_client_num;
    num_mutex.unlock();

    printf("%s left the chatroom. Online Users number: %d\n", data->name, current_client_num);

    // Join send thread
    send_thread[data->fd_id].join();

    return;
}

// Handle sending messages
void handle_send(Client *data) {
    while (1) {
        string message_buffer = data->message_q.pop();
        int n = message_buffer.length();
        int trans_len = BUFFER_LEN > n ? n : BUFFER_LEN;
        while (n > 0) {
            int len = send(data->socket, message_buffer.c_str(), trans_len, 0);
            if (len < 0) {
                perror("send");
                return;
            }
            n -= len;
            message_buffer.erase(0, len);
            trans_len = BUFFER_LEN > n ? n : BUFFER_LEN;
        }
        message_buffer.clear();
    }
}

// Handle receiving messages
void handle_recv(Client *data) {
    string message_buffer;
    int message_len = 0;

    char buffer[BUFFER_LEN + 1];
    int buffer_len = 0;

    while ((buffer_len = recv(data->socket, buffer, BUFFER_LEN, 0)) > 0) {
        for (int i = 0; i < buffer_len; i++) {
            if (message_len == 0) {
                char temp[100];
                sprintf(temp, "%s:", data->name);
                message_buffer = temp;
                message_len = message_buffer.length();
            }

            message_buffer += buffer[i];
            message_len++;

            if (buffer[i] == '\n') {
                // Decrypt the message
                string decryptedMessage = caesarDecrypt(message_buffer, 3);  // Using a shift of 3

                // Push message to other clients
                for (int j = 0; j < MAX_CLIENT_NUM; j++) {
                    if (client[j].valid && client[j].socket != data->socket) {
                        client[j].message_q.push(decryptedMessage);
                    }
                }
                message_len = 0;
                message_buffer.clear();
            }
        }
        buffer_len = 0;
        memset(buffer, 0, sizeof(buffer));
    }
}

// Caesar encryption
string caesarEncrypt(string text, int shift) {
    string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = (c - base + shift) % 26 + base;
        }
        result += c;
    }
    return result;
}

// Caesar decryption
string caesarDecrypt(string text, int shift) {
    return caesarEncrypt(text, 26 - shift);  // Decryption is the reverse of encryption
}

// Check if user exists in credentials file
bool userExists(const string &username) {
    ifstream file(CREDENTIALS_FILE);
    string line;
    while (getline(file, line)) {
        size_t pos = line.find(',');
        if (pos != string::npos && line.substr(0, pos) == username) {
            file.close();
            return true;
        }
    }
    file.close();
    return false;
}

// Validate user credentials
bool validateUser(const string &username, const string &password) {
    ifstream file(CREDENTIALS_FILE);
    string line;
    while (getline(file, line)) {
        size_t pos = line.find(',');
        if (pos != string::npos && line.substr(0, pos) == username) {
            string storedHashedPassword = line.substr(pos + 1);

            // Initialize the OpenSSL library
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();

            // Hash the provided password
            EVP_MD_CTX *mdctx;
            const EVP_MD *md;
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;

            md = EVP_get_digestbyname("sha256");
            if (!md) {
                return false; // SHA256 not found
            }

            mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, md, NULL);
            EVP_DigestUpdate(mdctx, password.c_str(), password.length());
            EVP_DigestFinal_ex(mdctx, md_value, &md_len);
            EVP_MD_CTX_free(mdctx);

            // Convert the hashed password to a string
            stringstream ss;
            for (int i = 0; i < md_len; i++) {
                ss << hex << setw(2) << setfill('0') << (int)md_value[i];
            }
            string hashedPassword = ss.str();

            file.close();
            // Compare the stored hashed password with the newly hashed password
            return storedHashedPassword == hashedPassword;
        }
    }
    file.close();
    return false;
}

// Add user to credentials file
bool addUser(const string &username, const string &password) {
    // Check if the username already exists
    if (userExists(username)) {
        cout << "Username already exists. Please choose a different username.\n";
        return false;
    }

    // Open the credentials file in append mode
    ofstream file(CREDENTIALS_FILE, ios_base::app);
    if (!file.is_open()) {
        return false;
    }

    // Initialize the OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Hash the password using SHA256
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_get_digestbyname("sha256");
    if (!md) {
        return false; // SHA256 not found
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password.c_str(), password.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // Convert the hashed password to a string
    stringstream ss;
    for (int i = 0; i < md_len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)md_value[i];
    }
    string hashedPassword = ss.str();

    // Store the username and hashed password in the file
    file << username << "," << hashedPassword << endl;
    file.close();
    return true;
}
