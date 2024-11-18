#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <syslog.h>
#include <minix/mthread.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <minix/mthread.h>
#include <errno.h>
#include <stddef.h>

// Define constants
#define SOCKET_PATH "/tmp/data_sharing_socket"
#define MAX_PENDING_CONNECTIONS 10

#define HMAC_SECRET "Hello"

#define BLOCK_NOT_FOUND 1 
#define ACCESS_DENIED 2

#define MAX_TOKENS 100  // Maximum number of tokens in the bucket
#define REFILL_RATE 5   // Tokens replenished per 10 second

#define MAX_TOTAL_MEMORY 104857600
#define MAX_BLOCK_SIZE 1048576

uint8_t failed_attempts = 0;
time_t failed_attempt_times[5];

int tokens = MAX_TOKENS;
mthread_mutex_t token_mutex;

size_t total_memory_used = 0;

// Function to refill tokens in the bucket
void refill_tokens(int sig) {
    mthread_mutex_lock(&token_mutex);
    if (tokens < MAX_TOKENS) {
        tokens = (tokens + REFILL_RATE <= MAX_TOKENS) ? tokens + REFILL_RATE : MAX_TOKENS;
    }
    mthread_mutex_unlock(&token_mutex);
}

// Function to consume tokens
bool consume_token() {
    mthread_mutex_lock(&token_mutex);
    if (tokens > 0) {
        tokens--;
        mthread_mutex_unlock(&token_mutex);
        return true;
    } else {
        mthread_mutex_unlock(&token_mutex);
        return false;
    }
}

void setup_timer() {
    struct itimerval timer;
    timer.it_interval.tv_sec = 10; // Refill tokens every 10 seconds
    timer.it_interval.tv_usec = 0;
    // Set initial timer expiration (in seconds)
    timer.it_value.tv_sec = 10; 
    timer.it_value.tv_usec = 0;
    // Set up signal handler for timer expiration
    signal(SIGALRM, refill_tokens);
    // Start the timer
    setitimer(ITIMER_REAL, &timer, NULL);
}

bool check_failed_attempts(){
  // Check if there are at least 5 failed attempts recorded
    if (failed_attempts < 5) {
        return false;
    }

    time_t first_attempt_time = failed_attempt_times[0];
    time_t fifth_attempt_time = failed_attempt_times[4];
    if (fifth_attempt_time - first_attempt_time <= 30) {
        // Reset the array and failed_attempts
        for (int i = 0; i < 5; ++i) {
            failed_attempt_times[i] = 0;
        }
        failed_attempts = 0;
        return true;
    } else {
        // Reset the array and failed_attempts
        for (int i = 0; i < 5; ++i) {
            failed_attempt_times[i] = 0;
        }
        failed_attempts = 0;
        return false;
    }

}

void add_attempt_time(){
    ++failed_attempts;
    for (int i = 0; i <= 5; ++i) {
        if (failed_attempt_times[i] == 0) {
            failed_attempt_times[i] = time(NULL); 
            return; 
        }
    }
}

// Function to generate HMAC signature
void generate_hmac(unsigned char *hmac_out) {
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, HMAC_SECRET, strlen(HMAC_SECRET), EVP_sha256(), NULL);
    HMAC_Final(&ctx, hmac_out, NULL);
    HMAC_CTX_cleanup(&ctx);
}

// Define structure for additional secrets
typedef struct AccessRecord {
    uint8_t secret[16];
    uint8_t permissions; 
    struct AccessRecord *next;
} AccessRecord;

// Define structure for data block
typedef struct DataBlock {
    char ID[256]; 
    uint8_t secret[16];
    AccessRecord *access_secrets;
    uint32_t data_length;
    void* data;
    time_t last_update;
    time_t last_read;
    struct DataBlock *next; 
} DataBlock;


// Global variable for storing data blocks (using linked list)
DataBlock* data_blocks_head = NULL;

void delete_idle_blocks() {
    time_t current_time = time(NULL);
    DataBlock* previous_block = NULL;
    DataBlock* current_block = data_blocks_head;
    
    while (current_block != NULL) {
        // Check if the block has a valid last read time
        if (current_block->last_read != 0) {
            // Calculate the time elapsed since the last read of the data block
            double elapsed_time = difftime(current_time, current_block->last_read);
            // Check if the elapsed time exceeds 10 mins
            if (elapsed_time > 600) {
                // Data block is idle, delete it
                if (previous_block != NULL) {
                    previous_block->next = current_block->next; // Update previous block's next pointer
                } else {
                    data_blocks_head = current_block->next; // Update head if the first block is idle
                }
                
                // Free memory occupied by data and the block itself
                total_memory_used -= sizeof(DataBlock) + current_block->data_length;
                free(current_block->data);
                free(current_block);
                // Move to the next block
                current_block = current_block->next;
                continue; // Skip the rest of the loop iteration
            }
        }
        
        // Move to the next block
        previous_block = current_block;
        current_block = current_block->next;
    }
}

DataBlock* create_data_block(const char *ID, const uint8_t *secret, uint32_t data_length, const void *data) {
    // Check if data length exceeds the maximum block size
    if (data_length > MAX_BLOCK_SIZE) {
        return NULL;
    }

    // Allocate memory for a new data block
    DataBlock* new_block = (DataBlock*)malloc(sizeof(DataBlock));
    if (new_block == NULL) {
        return NULL; 
    }

    // Calculate the size of the new block
    size_t block_size = sizeof(DataBlock) + data_length;

    // Check if there is enough memory available
    if (total_memory_used + block_size > MAX_TOTAL_MEMORY) {
        free(new_block); 
        return NULL;
    }

    // Update total memory used
    total_memory_used += block_size;
    
    // Copy ID, secret, and data_length to the new block
    strncpy(new_block->ID, ID, sizeof(new_block->ID) - 1);
    memcpy(new_block->secret, secret, sizeof(new_block->secret));
    new_block->data_length = data_length;

    // Allocate memory for data and copy it
    new_block->data = malloc(data_length);
    if (new_block->data == NULL) {
        free(new_block); 
        return NULL; 
    }
    memcpy(new_block->data, data, data_length);

    // Set last_update to the current time
    new_block->last_update = time(NULL);

    // Set next pointer to NULL
    new_block->next = NULL;

    return new_block; 
}

DataBlock* find_data_block(const char *ID, const uint8_t *secret, int *error) {
    // Iterate through existing data blocks to find the one with matching ID
    DataBlock *current_block = data_blocks_head;
    while (current_block != NULL) {
        // Compare IDs to find the matching block
        if (strcmp(current_block->ID, ID) == 0) {
            // Check if the provided secret matches the block's secret
            if (memcmp(current_block->secret, secret, sizeof(current_block->secret)) == 0) {
                return current_block; // ID and secret match, return the block
            } else {
                // Check if the provided secret matches any access control entry with permission value 1 or 3
                AccessRecord* entry = current_block->access_secrets;
                while (entry != NULL) {
                    if (memcmp(entry->secret, secret, sizeof(entry->secret)) == 0) {
                        // Secret matches an access control entry
                        if (entry->permissions == 1 || entry->permissions == 3) {
                            return current_block;
                        } else {
                            // Access denied due to insufficient permissions
                            *error = ACCESS_DENIED;
                            return NULL;
                        }
                    }
                    entry = entry->next;
                }
                // Provided secret doesn't match block's secret or any access control entry with sufficient permissions
                *error = ACCESS_DENIED;
                return NULL;
            }
        }
        current_block = current_block->next;
    }
    *error = BLOCK_NOT_FOUND; // ID not found
    return NULL;
}

bool check_data_valid(const char *ID, const uint8_t *secret) {
    int error;
    DataBlock* block = find_data_block(ID, secret, &error);
    if (block == NULL) {
        // Block with the given ID not found or access denied
        return false; 
    }

    if (block->last_read == 0) {
        // No last read time recorded, data is considered up to date
        return true;
    }

    // Check if the last update time is greater than the last read time
    if (block->last_update > block->last_read) {
        // Data has been updated since last read
        return false;
    } else {
        // Data is up to date
        return true;
    }
}

void add_data_block(DataBlock *new_block) {
    if (data_blocks_head == NULL) {
        // If the list is empty, set new_block as the head
        data_blocks_head = new_block;
    } else {
        // Find the last block in the list
        DataBlock *current_block = data_blocks_head;
        while (current_block->next != NULL) {
            current_block = current_block->next;
        }
        // Add new_block to the end of the list
        current_block->next = new_block;
    }
}

bool id_exists(const char *ID) {
    // Iterate through existing data blocks to check for ID
    DataBlock *current_block = data_blocks_head;
    while (current_block != NULL) {
        if (strcmp(current_block->ID, ID) == 0) {
            return true; // ID exists
        }
        current_block = current_block->next;
    }
    return false; // ID does not exist
}
int update_data_block(const char *ID, const uint8_t *secret, const void *new_data, uint32_t start_position, uint32_t new_data_length) {
    int error;
    DataBlock* block = find_data_block(ID, secret, &error);
    if (block == NULL) {
        // Block with the given ID not found or access denied
        return 8;
    }

    // Check if the provided secret matches the block's master secret
    if (memcmp(block->secret, secret, sizeof(block->secret)) == 0) {
        // Adjust start_position to remain within bounds
        start_position = (start_position < block->data_length) ? start_position : block->data_length;

        // Calculate the actual length of data to be updated
        uint32_t actual_length = (new_data_length <= block->data_length - start_position) ? new_data_length : block->data_length - start_position;

        // Copy new_data into the block's data starting at start_position
        memcpy((char *)block->data + start_position, new_data, actual_length);

        // Update the data length if necessary
        if (start_position + new_data_length > block->data_length) {
            block->data_length = start_position + new_data_length;
        }

        return 0; 
    }

    // If the provided secret doesn't match the master secret, check access control entries
    // Iterate over access control entries only if there are any
    if (block->access_secrets != NULL) {
        AccessRecord* entry = block->access_secrets;
        while (entry != NULL) {
            if (memcmp(entry->secret, secret, sizeof(entry->secret)) == 0) {
                // Check if the permissions allow write access (permission value 2 or 3)
                if (entry->permissions == 2 || entry->permissions == 3) {
                    // Adjust start_position to remain within bounds
                    start_position = (start_position < block->data_length) ? start_position : block->data_length;

                    // Check if the new data will cause buffer overflow
                    if (start_position + new_data_length > block->data_length) {
                        // New data exceeds the allocated memory for the block, it's an overflow
                        return 13;
                    }

                    // Copy new_data into the block's data starting at start_position
                    memcpy((char *)block->data + start_position, new_data, new_data_length);

                    // Update the data length if necessary
                    if (start_position + new_data_length > block->data_length) {
                        block->data_length = start_position + new_data_length;
                    }

                    return 0;
                } else {
                    // Insufficient permissions for write access
                    return 10;
                }
            }
            entry = entry->next;
        }
    }
    // If no matching access control entry found or no access control entries at all, return access denied
    return 8;
}

int update_access(const char *ID, const uint8_t *master_secret, const uint8_t *new_secret, int permissions){
  
    // Find the data block with the given ID
    int error;
    DataBlock* block = find_data_block(ID, master_secret, &error);
    if (block == NULL || error == ACCESS_DENIED) {
        // Access denied or block not found
        return 8;
    }

    // Check if the provided secret matches the block's master secret
    if (memcmp(block->secret, master_secret, sizeof(block->secret)) != 0) {
        // Access denied
        return 8;
    }

    // Check if the new secret already exists in the access control list
    AccessRecord* entry = block->access_secrets;
    while (entry != NULL) {
        if (memcmp(entry->secret, new_secret, sizeof(entry->secret)) == 0) {
            // New secret already exists, update permissions
            entry->permissions = permissions;
            return 0;
        }
        entry = entry->next;
    }

    // New secret doesn't exist, create a new access control entry
    AccessRecord* new_entry = (AccessRecord*)malloc(sizeof(AccessRecord));
    if (new_entry == NULL) {
        return 6;
    }
    memcpy(new_entry->secret, new_secret, sizeof(new_entry->secret));
    new_entry->permissions = permissions;
    new_entry->next = block->access_secrets;
    block->access_secrets = new_entry;

    syslog(LOG_INFO, "Association of new secret with buffer %s recorded.", ID);
    return 0;
}

void* handle_client_request(void*(arg)) {
    delete_idle_blocks();
    int client_socket = *((int*)arg);
    if (!consume_token()) {
        // No token available, reject request
        close(client_socket);
        free(arg); 
        return NULL;
    }

    // Receive command from client
    char command[256];
    ssize_t bytes_received = recv(client_socket, command, sizeof(command), 0);
    if (bytes_received <= 0) {
        perror("Error receiving command from client");
        int response = 6;
        send(client_socket, &response, sizeof(response), 0);
        close(client_socket);
        return NULL;
    }
    command[bytes_received] = '\0';

    if (strcmp(command, "sendNewBlock") == 0) {
        // Handle sendNewBlock command
        // Receive ID, secret, data_length, and data from client
        char ID[256];
        uint8_t secret[16];
        uint32_t data_length;
        void* data;

        bytes_received = recv(client_socket, ID, sizeof(ID), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }
        ID[bytes_received] = '\0';

        bytes_received = recv(client_socket, secret, sizeof(secret), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &data_length, sizeof(data_length), 0);
        if (bytes_received != sizeof(data_length)) {
            close(client_socket);
            return NULL;
        }
        
        data = malloc(data_length);
        if (!data) {
            close(client_socket);
            return NULL;
        }
        bytes_received = recv(client_socket, data, data_length, 0);
        if (bytes_received != data_length) {
            free(data);
            close(client_socket);
            return NULL;
        }

        // Check if ID already exists
        if (id_exists(ID)) {
            // Send error response to client indicating ID already in use
            int response = 12; 
            send(client_socket, &response, sizeof(response), 0);
            close(client_socket);
            free(data);
            return NULL;
        }

        DataBlock* new_block = create_data_block(ID, secret, data_length, data);
        if (new_block == NULL) {
            close(client_socket);
            free(data);
            return NULL;
        }
        
        add_data_block(new_block);
        free(data);

        int response = 0;
        send(client_socket, &response, sizeof(response), 0);

        unsigned char hmac_signature[EVP_MAX_MD_SIZE];
        generate_hmac(hmac_signature);
        send(client_socket, hmac_signature, 32, 0);
      
    } else if (strcmp(command, "getBlock") == 0) {
        // Handle getBlock command
        // Receive ID and secret from client
        char ID[256];
        uint8_t secret[16];
        uint32_t start_position;
        uint32_t length;
       
        bytes_received = recv(client_socket, ID, sizeof(ID), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }
        ID[bytes_received] = '\0';

        bytes_received = recv(client_socket, secret, sizeof(secret), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &start_position, sizeof(start_position), 0);
        if (bytes_received != sizeof(start_position)) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &length, sizeof(length), 0);
        if (bytes_received != sizeof(length)) {
            close(client_socket);
            return NULL;
        }

        unsigned char hmac_signature[EVP_MAX_MD_SIZE];
        generate_hmac(hmac_signature);
        send(client_socket, hmac_signature, 32, 0);

        int error;
        DataBlock* block = find_data_block(ID, secret, &error);
        if (block == NULL) {
            if (error == BLOCK_NOT_FOUND) {
                int response = 7;
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            } else if (error == ACCESS_DENIED) {
                int response = 8;
                add_attempt_time();
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            }
            return NULL;
        }

        int response = 0;
        send(client_socket, &response, sizeof(response), 0);

        // Determine the actual length to send
        uint32_t actual_length = (length <= block->data_length - start_position) ? length : block->data_length - start_position;
        // Adjust start_position to remain within bounds
        start_position = (start_position < block->data_length) ? start_position : block->data_length;

        ssize_t bytes_sent = send(client_socket, (char*)block->data + start_position, actual_length, 0);
        if (bytes_sent != actual_length) {
            perror("Error sending data to client");
            close(client_socket);
            return NULL;
        }

        block->last_read = time(NULL);

    } else if (strcmp(command, "updateBlock") == 0) {
        // Handle updateBlock command
        // Receive ID, secret, new data length, start position, and new data from client
        char ID[256];
        uint8_t secret[16];
        uint32_t new_data_length, start_position;
        void* new_data;

        bytes_received = recv(client_socket, ID, sizeof(ID), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }
        ID[bytes_received] = '\0';

        bytes_received = recv(client_socket, secret, sizeof(secret), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &new_data_length, sizeof(new_data_length), 0);
        if (bytes_received != sizeof(new_data_length)) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &start_position, sizeof(start_position), 0);
        if (bytes_received != sizeof(start_position)) {
            close(client_socket);
            return NULL;
        }

        new_data = malloc(new_data_length);
        if (!new_data) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, new_data, new_data_length, 0);
        if (bytes_received != new_data_length) {
            free(new_data);
            close(client_socket);
            return NULL;
        }
       
        unsigned char hmac_signature[EVP_MAX_MD_SIZE];
        generate_hmac(hmac_signature);
        send(client_socket, hmac_signature, 32, 0);
        
        int error;
        DataBlock* block = find_data_block(ID, secret, &error);
        if (block == NULL) {
            if (error == BLOCK_NOT_FOUND) {
                int response = 7;
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            } else if (error == ACCESS_DENIED) {
                add_attempt_time();
                int response = 8;
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            }
            return NULL;
        }
        block->last_read = time(NULL);

        if (check_data_valid(ID, secret) == true){
            int update_result = update_data_block(ID, secret, new_data, start_position, new_data_length);
            send(client_socket, &update_result, sizeof(update_result), 0);
            block->last_update = time(NULL);
            free(new_data); 
        }
        else if (check_data_valid(ID, secret) == false){
            int response = 9;
            send(client_socket, &response, sizeof(response), 0);
            free(new_data); 
        }
        
        }        
        else if (strcmp(command, "updateAccess") == 0) {
        // Handle updateaccess command
        // Receive ID, master_secret, new_secret, and permissions from client
        char ID[256];
        uint8_t secret[16];
        uint8_t new_secret[16];
        int permissions;

        bytes_received = recv(client_socket, ID, sizeof(ID), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }
        ID[bytes_received] = '\0';

        bytes_received = recv(client_socket, secret, sizeof(secret), 0);
      
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, new_secret, sizeof(new_secret), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        bytes_received = recv(client_socket, &permissions, sizeof(permissions), 0);
        if (bytes_received != sizeof(permissions)) {
            close(client_socket);
            return NULL;
        }

        unsigned char hmac_signature[EVP_MAX_MD_SIZE];
        generate_hmac(hmac_signature);
        send(client_socket, hmac_signature, 32, 0);

        // Call the updateAccess function
        uint8_t result = update_access(ID, secret, new_secret, permissions);
        if (result != 0) {
            send(client_socket, &result, sizeof(result), 0);
        } else {
            int response = 0;
            send(client_socket, &response, sizeof(response), 0);
        }
    } else if (strcmp(command, "checkDataValid") == 0) {
        // Receive ID, master_secret, new_secret, and permissions from client
        char ID[256];
        uint8_t secret[16];

        bytes_received = recv(client_socket, ID, sizeof(ID), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }
        ID[bytes_received] = '\0';

        bytes_received = recv(client_socket, secret, sizeof(secret), 0);
        if (bytes_received <= 0) {
            close(client_socket);
            return NULL;
        }

        unsigned char hmac_signature[EVP_MAX_MD_SIZE];
        generate_hmac(hmac_signature);
        send(client_socket, hmac_signature, 32, 0);

        int error;
        DataBlock* block = find_data_block(ID, secret, &error);
        if (block == NULL) {
            if (error == BLOCK_NOT_FOUND) {
                int response = 7;
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            } else if (error == ACCESS_DENIED) {
                int response = 8;
                send(client_socket, &response, sizeof(response), 0);
                close(client_socket);
            }
            return NULL;
        }
        block->last_read = time(NULL);
        bool result = check_data_valid(ID, secret);
        send(client_socket, &result, sizeof(result), 0);
    }
close(client_socket);    
return 0;
}

int main() {
    openlog("lpedated", LOG_PID, LOG_DAEMON);
    int server_socket, client_socket;
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    mthread_mutex_init(&token_mutex, NULL);

    server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket == -1) {
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    unlink(SOCKET_PATH);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_PENDING_CONNECTIONS) == -1) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Daemon listening on socket: %s\n", SOCKET_PATH);

    setup_timer();

    while (1) {
        // Accept connection
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == -1) {
            if (errno == EINTR) {
            // The accept call was interrupted by a signal, continue the loop
            continue;
            } else {
            syslog(LOG_NOTICE, "CONNECTION FAILED");
            continue;
            }
        }
        int* arg = malloc(sizeof(int));
        *arg = client_socket;

        mthread_thread_t thread;
        
        if (mthread_create(&thread, NULL, handle_client_request, (void*)arg) != 0) {
            close(client_socket);
            free(arg);
            continue;
        }
        mthread_join(thread, NULL);

        if (check_failed_attempts()){
            sleep(3);
        }

    }
    mthread_mutex_destroy(&token_mutex);
    close(server_socket);
    unlink(SOCKET_PATH);
    closelog();
    return 0;
}