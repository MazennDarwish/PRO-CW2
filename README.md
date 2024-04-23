# PRO-CW2
# Password Manager
## Introduction
The Chat Room Application is a multi-user communication platform allowing real-time text-based conversation. Developed in C++, it features client-server architecture, utilizing TCP/IP for reliable data transmission.
# Features
Client-Side Application:
User Registration and Authentication: Secure signup with SHA-256 password hashing.
Message Handling: Users can send encrypted messages using a Caesar cipher and receive decrypted messages.
Network Communication: Asynchronous socket programming for seamless user experience.
Server-Side Application:
Connection Management: Manages multiple client connections using thread pools.
User Authentication and Management: Secure username and password verification.
Message Distribution: Encrypted message broadcasting to all clients.

# Usage
Prerequisites:
C++ compiler (g++, clang)
OpenSSL libraries for hashing and encryption functions
Linux-based OS for supporting network and thread libraries
Compiling the Code:
Navigate to the directory containing the server and client programs.
Use the following commands:
bash
g++ -o server server_code.cpp -lssl -lcrypto
g++ -o client client_code.cpp -lssl -lcrypto
Ensure to include the OpenSSL library flags (-lssl -lcrypto).
Running the Server:
Start the server by typing ./server.
Follow the on-screen instructions to either sign up, log in, or exit.
Running the Client:
Run the client code by typing ./client.
Follow the on-screen prompts for user authentication or registration.

# Connect to the Chat Room:
After logging in, enter the server IP (typically 127.0.0.1) and the desired port (e.g., 9890).
You can then start chatting with other users connected to the chat room.
