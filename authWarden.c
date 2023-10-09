/*
 * authWarden - Secure TOTP Management Tool
 * Developed by: ifHoncho
 * GitHub: https://github.com/ifHoncho/authWarden
 * License: GNU General Public License v3.0
 *
 * For detailed documentation, visit the GitHub repository.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <oath.h>
#include <unistd.h> 

// Define storage paths and cryptographic constants
#define STORAGE_PATH "./encrypted_keys.dat"
#define BACKUP_PATH "./encrypted_keys_backup.dat"
#define SALT_LENGTH 8  // Consider using a longer salt for increased security
#define KEY_LENGTH 32
#define BLOCK_SIZE 16
#define PBKDF2_ITERATIONS 1000000  // 1 million iterations; consider making this configurable

// Forward declarations for functions
void initialize_storage(const char* password);
void add_service_key(const char* service, const char* key, const char* password);
char* get_service_key(const char* service, const char* password);
void generate_otp(const char* service, const char* password);
void handle_arguments(int argc, char *argv[]);
void backup_data();

int main(int argc, char *argv[]) {
    // Check for command-line arguments, if provided
    if(argc > 1) {
        handle_arguments(argc, argv);
        return 0;
    }

    // Variables for user input
    char choice[10];
    char service[256];
    char key[256];
    char password[256];
    char confirm_password[256];

    // Main interactive loop
    while (1) {
        // Display options to the user
        printf("Choose an option:\n");
        printf("1. add    - Add a new service key\n");
        printf("2. otp    - Generate OTP for a service\n");
        printf("3. backup - Create a backup of encrypted service keys\n");
        printf("4. exit   - Exit the program\n");
        printf("Enter choice: ");
        scanf("%9s", choice);  // Ensure buffer overflow is avoided

        if (strcmp(choice, "add") == 0) {
            // TODO: Implement a better input method to handle spaces and special characters in service names and keys
            printf("Enter service name: ");
            scanf("%255s", service);
            // Clear the input buffer
            int c;
            while ((c = getchar()) != '\n' && c != EOF);

            printf("Enter service key: ");
            scanf("%255s", key);
            // Clear the input buffer
            while ((c = getchar()) != '\n' && c != EOF);

            char* entered_password = getpass("Enter password: ");
            strncpy(password, entered_password, sizeof(password) - 1);  // Ensure null termination

            char* confirm_password = getpass("Confirm password: ");
            if (strcmp(password, confirm_password) != 0) {
                printf("Passwords do not match! Please try again.\n");
                continue;  // Return to the start of the loop
            }

            FILE *file_check = fopen(STORAGE_PATH, "r");
            if (!file_check) {
                // First time initialization
                initialize_storage(password);
            } else {
                fclose(file_check);
            }

            add_service_key(service, key, password);

            // Securely wipe sensitive data from memory
            OPENSSL_cleanse(password, sizeof(password));
            OPENSSL_cleanse(confirm_password, sizeof(confirm_password));

        } else if (strcmp(choice, "otp") == 0) {
            // TODO: Implement a better input method to handle spaces and special characters in service names
            printf("Enter service name: ");
            scanf("%255s", service);

            // Clear the input buffer
            int c;
            while ((c = getchar()) != '\n' && c != EOF);

            char* entered_password = getpass("Enter password: ");
            strncpy(password, entered_password, sizeof(password) - 1);  // Ensure null termination

            generate_otp(service, password);

            // Securely wipe sensitive data from memory
            OPENSSL_cleanse(password, sizeof(password));

        } else if (strcmp(choice, "backup") == 0) {
            backup_data();
        } else if (strcmp(choice, "exit") == 0) {
            printf("Exiting program.\n");
            break;
        } else {
            printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}

void handle_arguments(int argc, char *argv[]) {
    // Handle command-line inputs and perform the appropriate operations
    // TODO: Provide better error messages for incorrect usage
    if (argc < 3) {
        printf("Usage: ./genTwoFa <command> [options]\n");
        printf("Commands:\n");
        printf("  init <password>           - Initialize storage\n");
        printf("  add <service> <key> <password> - Add a service key\n");
        printf("  otp <service> <password>  - Generate OTP for a service\n");
        return;
    }
    
    const char* command = argv[1];
    if (strcmp(command, "init") == 0 && argc == 3) {
        initialize_storage(argv[2]);
    } else if (strcmp(command, "add") == 0 && argc == 5) {
        add_service_key(argv[2], argv[3], argv[4]);
    } else if (strcmp(command, "otp") == 0 && argc == 4) {
        generate_otp(argv[2], argv[3]);
    } else {
        printf("Unknown or incomplete command: %s\n", command);
        printf("Run without arguments for interactive mode.\n");
    }
}

void initialize_storage(const char* password) {
    // Initialize the storage by creating a new encryption key derived from the user's password and a random salt
    // TODO: Consider error handling for file write failures, and check if storage file already exists before initializing
    unsigned char salt[SALT_LENGTH];
    unsigned char key[KEY_LENGTH];

    if (RAND_bytes(salt, SALT_LENGTH) != 1) {
        printf("Error generating random salt.\n");
        return;
    }

    FILE *file_check = fopen(STORAGE_PATH, "r");
    if (!file_check) {
        FILE *file_create = fopen(STORAGE_PATH, "wb");
        if (!file_create) {
            printf("Error initializing storage file.\n");
            return;
        }
        fclose(file_create);
    } else {
        fclose(file_check);
    }

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LENGTH, key) != 1) {
        printf("Error deriving encryption key.\n");
        return;
    }

    FILE *file = fopen(STORAGE_PATH, "wb");
    if (!file) {
        printf("Error opening storage file for writing.\n");
        return;
    }

    fwrite(salt, 1, SALT_LENGTH, file);
    fclose(file);

    printf("Storage initialized successfully.\n");
}

void add_service_key(const char* service, const char* key, const char* password) {
    // Adds a new service key by encrypting it and then storing it with the service name, IV, and a HMAC for integrity verification
    // TODO: Ensure the entire file isn't read into memory (scalability concern for large number of services)
    unsigned char salt[SALT_LENGTH];
    unsigned char derived_key[KEY_LENGTH];
    unsigned char iv[BLOCK_SIZE];
    unsigned char encrypted_key[BLOCK_SIZE * 2];  // Potential buffer overflow risk if the encrypted key exceeds this size
    unsigned char hmac_value[EVP_MAX_MD_SIZE];

    FILE *file = fopen(STORAGE_PATH, "r+b");
    if (!file) {
        perror("Error opening storage file in add_service_key");
        return;
    }

    fread(salt, 1, SALT_LENGTH, file);

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LENGTH, derived_key) != 1) {
        printf("Error deriving encryption key.\n");
        return;
    }

    if (RAND_bytes(iv, BLOCK_SIZE) != 1) {
        printf("Error generating random IV.\n");
        return;
    }

    // Encrypt the service key using AES-CBC
    // TODO: Consider error handling for encryption failures
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context.\n");
        return;
    }
    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv) != 1) {
        printf("Error initializing encryption.\n");
        return;
    }
    if (EVP_EncryptUpdate(ctx, encrypted_key, &len, (unsigned char*)key, strlen(key)) != 1) {
        printf("Error during encryption.\n");
        return;
    }
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_key + len, &len) != 1) {
        printf("Error finalizing encryption.\n");
        return;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    fseek(file, 0, SEEK_END);

    unsigned short service_name_len = strlen(service);
    fwrite(&service_name_len, sizeof(service_name_len), 1, file);
    fwrite(service, 1, service_name_len, file);
    fwrite(iv, 1, BLOCK_SIZE, file);
    fwrite(&ciphertext_len, sizeof(ciphertext_len), 1, file);
    fwrite(encrypted_key, 1, ciphertext_len, file);

    // Compute HMAC for integrity verification
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_content = (unsigned char*)malloc(file_size);
    fread(file_content, 1, file_size, file);

    unsigned int hmac_len;
    HMAC(EVP_sha256(), derived_key, KEY_LENGTH, file_content, file_size, hmac_value, &hmac_len);

    fwrite(hmac_value, 1, hmac_len, file);

    fclose(file);
    free(file_content);

    printf("Service key added successfully.\n");
    OPENSSL_cleanse(derived_key, KEY_LENGTH);
}

char* get_service_key(const char* service, const char* password) {
    // Retrieves an encrypted service key, decrypts it, and returns the decrypted key
    // TODO: Ensure the entire file isn't read into memory (scalability concern for large number of services)
    unsigned char salt[SALT_LENGTH];
    unsigned char derived_key[KEY_LENGTH];
    unsigned char iv[BLOCK_SIZE];
    unsigned char encrypted_key[BLOCK_SIZE * 2];  // Potential buffer overflow risk if the encrypted key exceeds this size
    unsigned char hmac_value[EVP_MAX_MD_SIZE];
    unsigned char stored_hmac[EVP_MAX_MD_SIZE];
    unsigned short service_name_len;
    char read_service[256];
    unsigned char *decrypted_key = NULL;

    FILE *file = fopen(STORAGE_PATH, "rb");
    if (!file) {
        perror("Error opening storage file in get_service_key");
        return NULL;
    }

    fread(salt, 1, SALT_LENGTH, file);

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, PBKDF2_ITERATIONS, EVP_sha256(), KEY_LENGTH, derived_key) != 1) {
        printf("Error deriving encryption key.\n");
        fclose(file);
        return NULL;
    }

    // Verify the HMAC for data integrity
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *file_content = (unsigned char*)malloc(file_size - EVP_MD_size(EVP_sha256()));
    fread(file_content, 1, file_size - EVP_MD_size(EVP_sha256()), file);

    unsigned int hmac_len;
    HMAC(EVP_sha256(), derived_key, KEY_LENGTH, file_content, file_size - EVP_MD_size(EVP_sha256()), hmac_value, &hmac_len);
    free(file_content);

    fseek(file, file_size - EVP_MD_size(EVP_sha256()), SEEK_SET);
    fread(stored_hmac, 1, EVP_MD_size(EVP_sha256()), file);

    if (CRYPTO_memcmp(hmac_value, stored_hmac, hmac_len) != 0) {
        printf("Data integrity check failed. Exiting.\n");
        fclose(file);
        return NULL;
    }

    fseek(file, SALT_LENGTH, SEEK_SET);
    while (!feof(file)) {
        if (fread(&service_name_len, sizeof(service_name_len), 1, file) == 0) {
            break;
        }
        fread(read_service, 1, service_name_len, file);
        read_service[service_name_len] = '\0';

        if (strcmp(service, read_service) == 0) {
            // Match found; decrypt the key
            fread(iv, 1, BLOCK_SIZE, file);
            unsigned short encrypted_key_len;
            fread(&encrypted_key_len, sizeof(encrypted_key_len), 1, file);
            if (encrypted_key_len > sizeof(encrypted_key)) {
                printf("Error: encrypted key length exceeds buffer size.\n");
                fclose(file);
                return NULL;
            }
            fread(encrypted_key, 1, encrypted_key_len, file);

            decrypted_key = (unsigned char *)malloc(encrypted_key_len + 1);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                printf("Error creating cipher context.\n");
                free(decrypted_key);
                fclose(file);
                return NULL;
            }
            int len;
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv) != 1 ||
                EVP_DecryptUpdate(ctx, decrypted_key, &len, encrypted_key, encrypted_key_len) != 1) {
                printf("Error during decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                free(decrypted_key);
                fclose(file);
                return NULL;
            }
            int plaintext_len = len;
            if (EVP_DecryptFinal_ex(ctx, decrypted_key + len, &len) != 1) {
                printf("Error finalizing decryption.\n");
                EVP_CIPHER_CTX_free(ctx);
                free(decrypted_key);
                fclose(file);
                return NULL;
            }
            plaintext_len += len;
            decrypted_key[plaintext_len] = '\0';
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return (char*)decrypted_key;
        } else {
            // Move past the current service data
            fseek(file, BLOCK_SIZE, SEEK_CUR);
            unsigned short encrypted_key_len;
            fread(&encrypted_key_len, sizeof(encrypted_key_len), 1, file);
            fseek(file, encrypted_key_len, SEEK_CUR);
        }
    }

    printf("Service name not found.\n");
    fclose(file);
    return NULL;
}

void generate_otp(const char* service, const char* password) {
    // Uses the OATH library to generate a TOTP for a specified service using its key
    char* service_key = get_service_key(service, password);
    if (!service_key) {
        printf("Error retrieving service key for %s.\n", service);
        return;
    }

    size_t bin_key_len = strlen(service_key) / 2;
    unsigned char bin_key[bin_key_len];
    for (size_t i = 0; i < bin_key_len; i++) {
        sscanf(service_key + 2*i, "%2hhx", &bin_key[i]);
    }

    char otp[10];
    if (oath_totp_generate(bin_key, bin_key_len, time(NULL), 30, 0, 6, otp) != OATH_OK) {
        printf("Error generating OTP.\n");
        return;
    }

    printf("Generated OTP for %s: %s\n", service, otp);
    free(service_key);
}

void backup_data() {
    // Makes a backup of the encrypted keys by copying the storage file to a backup location
    // TODO: Handle cases where a backup already exists, potentially overwriting it
    FILE *original = fopen(STORAGE_PATH, "rb");
    FILE *backup = fopen(BACKUP_PATH, "wb");

    if (!original || !backup) {
        printf("Error creating backup.\n");
        return;
    }

    char ch;
    while ((ch = fgetc(original)) != EOF) {
        fputc(ch, backup);
    }

    fclose(original);
    fclose(backup);
    printf("Backup created successfully at %s.\n", BACKUP_PATH);
}
