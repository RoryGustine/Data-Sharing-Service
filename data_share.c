#include "data_share.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define SOCKET_PATH "/tmp/data_sharing_socket"
#define HMAC_SECRET "Hello"

// Function to generate HMAC signature
void generate_hmac(unsigned char *hmac_out) {
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, HMAC_SECRET, strlen(HMAC_SECRET), EVP_sha256(), NULL);
    HMAC_Final(&ctx, hmac_out, NULL);
    HMAC_CTX_cleanup(&ctx);
}

uint8_t sendNewBlock(const char *ID, const uint8_t *secret, uint32_t data_length, const void *data) {
    
    size_t actual_data_length = strlen((const char *)data); 
    if (actual_data_length != data_length) {
        return 3;
    }

    if (actual_data_length > 1000){
        return 3;
    }
    
    size_t send_id_length = strlen(ID);
    if (send_id_length > 255) {
        return 3;
    }

    // Create the socket and connect
    int client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        return 1; 
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return 2; 
    }

    // Send command to the server
    char command[] = "sendNewBlock";
    if (send(client_socket, command, sizeof(command), 0) == -1) {
        close(client_socket);
        return 3;
    }

    // Send ID
    size_t id_length = strlen(ID);
    ssize_t bytes_sent = send(client_socket, ID, id_length, 0);
    if (bytes_sent != id_length) {
        close(client_socket);
        return 3; 
    }

    // Send secret
    bytes_sent = send(client_socket, secret, sizeof(secret), 0);
    if (bytes_sent != sizeof(secret)) {
        close(client_socket);
        return 3;
    }

    // Send data_length
    bytes_sent = send(client_socket, &data_length, sizeof(data_length), 0);
    if (bytes_sent != sizeof(data_length)) {
        close(client_socket);
        return 3; 
    }

    // Send data
    bytes_sent = send(client_socket, data, data_length, 0);
    if (bytes_sent != data_length) {
        close(client_socket);
        return 3; 
    }


    int response;
    ssize_t response_received = recv(client_socket, &response, sizeof(response), 0);
    if (response_received == -1) {
        close(client_socket);
        return 6;
    } else if (response_received == 0) {
        close(client_socket);
        return 5; 
    }

    unsigned char hmac_signature[EVP_MAX_MD_SIZE];
    ssize_t auth_received = recv(client_socket, hmac_signature, 32, 0);

    if (auth_received > 0) {
        unsigned char local_hmac[EVP_MAX_MD_SIZE];
        generate_hmac(local_hmac);
        // Compare received HMAC signature with local HMAC signature
        if (memcmp(hmac_signature, local_hmac, 32) != 0) {
            return 11;
        }
    } 
   
    close(client_socket);
    return response; 
}

uint8_t updateBlock(const char *ID, const uint8_t *secret, const void *new_data, uint32_t new_data_length, uint32_t start_position) {
    
    size_t update_id_length = strlen(ID);
    if (update_id_length > 255) {
        return 3;
    }

    size_t actual_data_length = strlen((const char *)new_data); 
    if (actual_data_length != new_data_length) {
        return 3;
    }

    // Create the socket and connect
    int client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        return 1;
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return 2; 
    }

    // Send command to the server
    char command[] = "updateBlock";
    if (send(client_socket, command, sizeof(command), 0) == -1) {
        close(client_socket);
        return 3; 
    }

    // Send ID
    size_t id_length = strlen(ID);
    ssize_t bytes_sent = send(client_socket, ID, id_length, 0);
    if (bytes_sent != id_length) {
        close(client_socket);
        return 3; 
    }

    // Send secret
    bytes_sent = send(client_socket, secret, sizeof(secret), 0);
    if (bytes_sent != sizeof(secret)) {
        close(client_socket);
        return 3; 
    }

    // Send new_data_length to the server
    bytes_sent = send(client_socket, &new_data_length, sizeof(new_data_length), 0);
    if (bytes_sent != sizeof(new_data_length)) {
        close(client_socket);
        return 3; 
    }

    // Send start_position to the server
    bytes_sent = send(client_socket, &start_position, sizeof(start_position), 0);
    if (bytes_sent != sizeof(start_position)) {
        close(client_socket);
        return 3; 
    }

    // Send new data to the server
    bytes_sent = send(client_socket, new_data, new_data_length, 0);
    if (bytes_sent != new_data_length) {
        close(client_socket);
        return 3; 
    }

    unsigned char hmac_signature[EVP_MAX_MD_SIZE];
    ssize_t auth_received = recv(client_socket, hmac_signature, 32, 0);
    
    unsigned char local_hmac[EVP_MAX_MD_SIZE];
    generate_hmac(local_hmac);

    // Compare received HMAC signature with local HMAC signature
    if (memcmp(hmac_signature, local_hmac, 32) != 0) {
        return 11;
    } 

    int response;
    ssize_t response_received = recv(client_socket, &response, sizeof(response), 0);
    if (response_received == -1) {
        close(client_socket);
        return 6; 
    } else if (response_received == 0) {
        close(client_socket);
        return 5; 
    }

    close(client_socket);

    return response; 
}

uint8_t getBlock(const char *ID, const uint8_t *secret, uint32_t buffer_size, void *buffer, uint32_t start_position, uint32_t length) {

    // Create the socket and connect
    int client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        return 1; 
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return 2; 
    }

    // Send command to the server
    char command[] = "getBlock";
    if (send(client_socket, command, sizeof(command), 0) == -1) {
        close(client_socket);
        return 3;
    }

    // Send ID
    size_t id_length = strlen(ID);
    ssize_t bytes_sent = send(client_socket, ID, id_length, 0);
    if (bytes_sent != id_length) {
        close(client_socket);
        return 3; 
    }

    // Send secret
    bytes_sent = send(client_socket, secret, sizeof(secret), 0);
    if (bytes_sent != sizeof(secret)) {
        close(client_socket);
        return 3;
    }

    // Send start_position to the server
    bytes_sent = send(client_socket, &start_position, sizeof(start_position), 0);
    if (bytes_sent != sizeof(start_position)) {
        close(client_socket);
        return 3; 
    }

    // Send length to the server
    bytes_sent = send(client_socket, &length, sizeof(length), 0);
    if (bytes_sent != sizeof(length)) {
        close(client_socket);
        return 3; 
    }

    unsigned char hmac_signature[EVP_MAX_MD_SIZE];
    ssize_t auth_received = recv(client_socket, hmac_signature, 32, 0);
    
    unsigned char local_hmac[EVP_MAX_MD_SIZE];
    generate_hmac(local_hmac);

    // Compare received HMAC signature with local HMAC signature
    if (memcmp(hmac_signature, local_hmac, 32) != 0) {
        return 11;
    } 

    int response;
    ssize_t response_received = recv(client_socket, &response, sizeof(response), 0);
    if (response_received == -1) {
        close(client_socket);
        return 6; 
    } else if (response_received == 0) {
        close(client_socket);
        return 5;
    }

    if (response != 6 && response != 7 && response != 8){
        // Receive data block from the server and store it in buffer
        ssize_t bytes_received = recv(client_socket, buffer, buffer_size, 0);
        if (bytes_received == -1) {
            close(client_socket);
            return 4; 
        } else if (bytes_received == 0) {
            close(client_socket);
            return 5; 
    }
    }

    close(client_socket);

    return response; 
}

uint8_t updateAccess(const char *ID, const uint8_t *secret, const uint8_t *new_secret, int permissions){
    
    size_t input_id_length = strlen(ID);
    if (input_id_length > 255) {
        return 3;
    }
    
    // Create the socket and connect
    int client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        return 1;
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return 2; 
    }

    // Send command to the server
    char command[] = "updateAccess";
    if (send(client_socket, command, sizeof(command), 0) == -1) {
        close(client_socket);
        return 3; 
    }

    // Send ID to the server
    size_t id_length = strlen(ID);
    ssize_t bytes_sent = send(client_socket, ID, id_length, 0);
    if (bytes_sent != id_length) {
        close(client_socket);
        return 3;
    }

    // Send master secret to the server
    bytes_sent = send(client_socket, secret, sizeof(secret), 0);
    if (bytes_sent != sizeof(secret)) {
        close(client_socket);
        return 3; 
    }

    // Send new secret to the server
    bytes_sent = send(client_socket, new_secret, sizeof(new_secret), 0);
    if (bytes_sent != sizeof(new_secret)) {
        close(client_socket);
        return 3;
    }

    // Send permissions to the server
    bytes_sent = send(client_socket, &permissions, sizeof(permissions), 0);
    if (bytes_sent != sizeof(permissions)) {
        close(client_socket);
        return 3;
    }

    unsigned char hmac_signature[EVP_MAX_MD_SIZE];
    ssize_t auth_received = recv(client_socket, hmac_signature, 32, 0);
    
    unsigned char local_hmac[EVP_MAX_MD_SIZE];
    generate_hmac(local_hmac);

    // Compare received HMAC signature with local HMAC signature
    if (memcmp(hmac_signature, local_hmac, 32) != 0) {
        return 11;
    } 

    // Receive response from the server
    int response;
    ssize_t response_received = recv(client_socket, &response, sizeof(response), 0);
    if (response_received == -1) {
        close(client_socket);
        return 4; 
    } else if (response_received == 0) {
        close(client_socket);
        return 5; 
    }

    close(client_socket);

    return response;
}

bool checkDataValid(const char *ID, const uint8_t *secret){

    // Create the socket and connect
    int client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        return 1; 
    }

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return 2; 
    }

    // Send command to the server
    char command[] = "checkDataValid";
    if (send(client_socket, command, sizeof(command), 0) == -1) {
        close(client_socket);
        return 3; 
    }

    // Send ID to the server
    size_t id_length = strlen(ID);
    ssize_t bytes_sent = send(client_socket, ID, id_length, 0);
    if (bytes_sent != id_length) {
        close(client_socket);
        return 3; 
    }

    // Send secret to the server
    bytes_sent = send(client_socket, secret, sizeof(secret), 0);
    if (bytes_sent != sizeof(secret)) {
        close(client_socket);
        return 3; 
    }

    unsigned char hmac_signature[EVP_MAX_MD_SIZE];
    ssize_t auth_received = recv(client_socket, hmac_signature, 32, 0);
    
    unsigned char local_hmac[EVP_MAX_MD_SIZE];
    generate_hmac(local_hmac);

    // Compare received HMAC signature with local HMAC signature
    if (memcmp(hmac_signature, local_hmac, 32) != 0) {
        return 11;
    } 

    bool response;
    recv(client_socket, &response, sizeof(response), 0); 
    return response;
}

