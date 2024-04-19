#include <iostream>
#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <iomanip>
#include <sstream>

using namespace std;

#define BUFFER_LEN 1024
#define NAME_LEN 20
#define CREDENTIALS_FILE "client.txt"

struct Credentials {
    char username[NAME_LEN + 1];
    char password[NAME_LEN + 1];
};

char name[NAME_LEN + 1];

void handle_recv(int client_sock) {
    string message_buffer;
    int message_len = 0;
    char buffer[BUFFER_LEN + 1];
    int buffer_len = 0;

    while ((buffer_len = recv(client_sock, buffer, BUFFER_LEN, 0)) > 0) {
        for (int i = 0; i < buffer_len; i++) {
            if (message_len == 0)
                message_buffer = buffer[i];
            else
                message_buffer += buffer[i];

            message_len++;

            if (buffer[i] == '\n') {
                cout << message_buffer << endl;
                message_len = 0;
                message_buffer.clear();
            }
        }
        memset(buffer, 0, sizeof(buffer));
    }
    printf("The Server has been shutdown!\n");
}

bool signup(const char* username, const char* password) {
    ifstream file(CREDENTIALS_FILE);
    if (file.is_open()) {
        string stored_username;
        while (file >> stored_username) {
            if (stored_username == username) {
                cout << "Username already exists. Please choose a different username.\n";
                file.close();
                return false;
            }
        }
        file.close();
    }

    ofstream outfile(CREDENTIALS_FILE, ios::app);
    if (!outfile.is_open()) {
        cerr << "Failed to open file for writing." << endl;
        return false;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_get_digestbyname("sha256");
    if (!md) {
        cerr << "SHA256 not found." << endl;
        return false; 
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (int i = 0; i < md_len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)md_value[i];
    }
    string hashedPassword = ss.str();

    outfile << username << ' ' << hashedPassword << endl;
    outfile.close();
    return true;
}

bool login(const char* username, const char* password) {
    ifstream file(CREDENTIALS_FILE);
    if (!file.is_open()) {
        cerr << "Failed to open file for reading." << endl;
        return false;
    }

    string stored_username, stored_password;
    while (file >> stored_username >> stored_password) {
        if (stored_username == username) {
            EVP_MD_CTX *mdctx;
            const EVP_MD *md;
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;

            md = EVP_get_digestbyname("sha256");
            if (!md) {
                cerr << "SHA256 not found." << endl;
                return false;
            }

            mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, md, NULL);
            EVP_DigestUpdate(mdctx, password, strlen(password));
            EVP_DigestFinal_ex(mdctx, md_value, &md_len);
            EVP_MD_CTX_free(mdctx);

            stringstream ss;
            for (int i = 0; i < md_len; i++) {
                ss << hex << setw(2) << setfill('0') << (int)md_value[i];
            }
            string hashedPassword = ss.str();

            if (stored_password == hashedPassword) {
                file.close();
                return true;
            }
        }
    }
    file.close();
    return false;
}

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

int main() {
    char choice;
    printf("Welcome to the chat application!\n");
    while (1) {
        printf("1. Sign up\n2. Login\n3. Exit\nEnter your choice: ");
        cin >> choice;
        getchar(); 

        switch (choice) {
            case '1': {
                char username[NAME_LEN + 1], password[NAME_LEN + 1];
                printf("Enter your desired username: ");
                cin.getline(username, NAME_LEN);
                printf("Enter your password: ");
                cin.getline(password, NAME_LEN);

                while (!signup(username, password)) {
                    cout << "Failed to sign up. Please try again." << endl;
                    printf("Enter your desired username: ");
                    cin.getline(username, NAME_LEN);
                    printf("Enter your password: ");
                    cin.getline(password, NAME_LEN);
                }
                cout << "Signup successful! You've been automatically logged in." << endl;

                strcpy(name, username);

                break;
            }
            case '2': {
                char username[NAME_LEN + 1], password[NAME_LEN + 1];
                printf("Enter your username: ");
                cin.getline(username, NAME_LEN);
                printf("Enter your password: ");
                cin.getline(password, NAME_LEN);

                if (!login(username, password)) {
                    cout << "Invalid username or password. Please try again." << endl;
                    continue;
                }
                strcpy(name, username);

                cout << "Welcome back, " << name << "!" << endl;
                break;
            }
            case '3':
                cout << "Exiting the chat application. Goodbye!" << endl;
                return 0;
            default:
                cout << "Invalid choice. Please try again." << endl;
                break;
        }

        int client_sock;
        if ((client_sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("socket");
            return -1;
        }
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;

        int server_port = 0;
        char server_ip[16] = {0};
        while (1) {
            printf("Please enter IP address of the server: ");
            scanf("%s", server_ip);
            printf("Please enter port number of the server: ");
            scanf("%d", &server_port);
            getchar();

            addr.sin_port = htons(server_port);
            addr.sin_addr.s_addr = inet_addr(server_ip);
            if (connect(client_sock, (struct sockaddr *)&addr, sizeof(addr))) {
                perror("connect");
                continue;
            }
            break;
        }

        printf("Connecting......");
        fflush(stdout);
        char state[10] = {0};
        if (recv(client_sock, state, sizeof(state), 0) < 0) {
            perror("recv");
            return -1;
        }
        if (strcmp(state, "OK")) {
            printf("\rThe chatroom is already full!\n");
            return 0;
        } else {
            printf("\rConnect Successfully!\n");
        }

        if (send(client_sock, name, strlen(name), 0) < 0) {
            perror("send");
            return -1;
        }

        thread recv_thread(handle_recv, client_sock);

        while (1) {
            char message[BUFFER_LEN + 1];
            cin.get(message, BUFFER_LEN);
            int n = strlen(message);
            if (cin.eof()) {
                cin.clear();
                clearerr(stdin);
                continue;
            } else if (n == 0) {
                cin.clear();
                clearerr(stdin);
            }
            if (n > BUFFER_LEN - 2) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                printf("Reached the upper limit of the words!\n");
                continue;
            }
            cin.get();
            message[n] = '\n';
            message[n + 1] = '\0';
            n++;
            printf("\n");

            string encryptedMessage = caesarEncrypt(string(message), 3);

            int sent_len = 0;
            int trans_len = BUFFER_LEN > n ? n : BUFFER_LEN;

            while (n > 0) {
                int len = send(client_sock, encryptedMessage.c_str() + sent_len, trans_len, 0);
                if (len < 0) {
                    perror("send");
                    return -1;
                }
                n -= len;
                sent_len += len;
                trans_len = BUFFER_LEN > n ? n : BUFFER_LEN;
            }
            memset(message, 0, sizeof(message));
        }

        recv_thread.join();
        shutdown(client_sock, 2);
    }
    return 0;
}
