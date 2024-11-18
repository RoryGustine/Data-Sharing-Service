#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "data_share.h"
#include <stdbool.h>

#define SUCCESS 0
#define SOCKET_CREATE_FAIL 1
#define FAILED_TO_CONNECT 2
#define ERROR_SENDING 3
#define ERROR_RECIEVING_BLOCK 4
#define CONNECTION_CLOSED 5
#define ERROR_RECIEVING_RESPONSE 6
#define AUTH_FAIL 11
#define ID_EXISTS 12

int main() {
    // Test data
    const char *ID = "TESTBLOCK";
    const uint8_t secret[] = {0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98};
    uint32_t data_length = 11;
    const void *data = "TESTINGDATA";

    // Send new data block
    printf("Sending new data block...\n");
    uint8_t result_send = sendNewBlock(ID, secret, data_length, data);
    switch (result_send) {
        case SUCCESS:
            printf("New data block sent successfully!\n");
            break;
        case SOCKET_CREATE_FAIL:
            printf("Socket creation failed.\n");
            break;
        case FAILED_TO_CONNECT:
            printf("Failed to connect to server.\n");
            break;
        case ERROR_SENDING:
            printf("Error sending data to server.\n");
            break;
        case CONNECTION_CLOSED:
            printf("Connection closed by server.\n");
            break;
        case ERROR_RECIEVING_RESPONSE:
            printf("No response from server.\n");
            break;
        case AUTH_FAIL:
            printf("Authentication failed.\n");
            break;
        case ID_EXISTS:
            printf("ID already exists.\n");
            break;
        default:
            printf("Unknown error occurred.\n");
            break;
    }

}