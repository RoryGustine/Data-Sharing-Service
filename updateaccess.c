#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "data_share.h"

#define SUCCESS 0
#define SOCKET_CREATE_FAIL 1
#define FAILED_TO_CONNECT 2
#define ERROR_SENDING 3
#define ERROR_RECIEVING_BLOCK 4
#define CONNECTION_CLOSED 5
#define ERROR_RECIEVING_RESPONSE 6
#define BLOCK_NOT_FOUND 7
#define ACCESS_DENIED 8
#define AUTH_FAIL 11

int main(){
    // Test data
    const char *ID = "TESTBLOCK";
    const uint8_t secret[] = {0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98, 0x12, 0x14, 0x11, 0x98};

    printf("Updating Access...\n");
    const uint8_t newsecret[] = {0x20, 0x32, 0x11, 0x55,0x20, 0x32, 0x11, 0x55,0x20, 0x32, 0x11, 0x55,0x20, 0x32, 0x11, 0x55};
    int permission = 1;
    uint8_t result_access_update = updateAccess(ID, secret, newsecret, permission);
    switch (result_access_update) {
        case SUCCESS:
            printf("Access control updated successfully!\n");
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
        case ERROR_RECIEVING_RESPONSE:
            printf("No response from server.\n");
            break;
        case BLOCK_NOT_FOUND:
            printf("Block not found.\n");
            break;
        case ACCESS_DENIED:
            printf("Access denied.\n");
            break;
        case AUTH_FAIL:
            printf("Authentication failed.\n");
            break;
        default:
            printf("Unknown error occurred.\n");
            break;
    }
   
    return 0;
}