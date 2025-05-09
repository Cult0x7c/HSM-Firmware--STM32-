/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "crc.h"
#include "dma.h"
#include "rng.h"
#include "rtc.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "cmox_crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "string.h"
#include "stm32g4xx_hal.h"

#include "stm32g4xx_hal_flash.h"
#include "stm32g4xx_hal_flash_ex.h"

#include "stm32g4xx_ll_rcc.h"
#include "stm32g4xx_ll_utils.h"
#include "stm32g4xx_ll_pwr.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */

uint8_t single_byte;

#define SHARED_SECRET_SIZE 32  // ECDH Shared Secret (256-bit key -> 32 bytes)
uint8_t computed_secret[SHARED_SECRET_SIZE];  // Buffer to store shared secret
size_t computed_size;  // Size of shared secret


/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#define ECC_CURVE_PARAMS CMOX_ECC_CURVE_SECP256R1 // Example curve (secp256r1)
#define RANDOM_BUFFER_SIZE 32                       // Size of the random buffer
#define ECC_PRIVATE_KEY_SIZE 32                     // Size for secp256r1 (256 bits / 8 = 32 bytes)
#define ECC_PUBLIC_KEY_SIZE 64                      // Public key (X and Y each 32 bytes)
#define MESSAGE_MAX_LEN 256   						// Maximum message length
#define SIGNATURE_SIZE 64     						// ECDSA signature (32-Byte R + 32-Byte S)
#define CMOX_SHA256_SIZE 32							// CMOX_SHA256_SIZE 32 byte
#define NUM_KEYS 3									// Amount of keys

#define LOG_FLASH_START_ADDR   0x0807F800U      // last page in 512KB flash
#define LOG_FLASH_PAGE_SIZE    2048U
#define LOG_MESSAGE_SIZE 64
#define LOG_ENTRY_SIZE (LOG_MESSAGE_SIZE+32)
#define LOG_MAX_ENTRIES        (LOG_FLASH_PAGE_SIZE / LOG_ENTRY_SIZE)

#define FLASH_BASE_ADDR     0x08000000U
#define FLASH_PAGE_NUMBER   ((LOG_FLASH_START_ADDR - FLASH_BASE_ADDR) / LOG_FLASH_PAGE_SIZE)

uint8_t private_keys[NUM_KEYS][ECC_PRIVATE_KEY_SIZE]; // Array for private keys
uint8_t public_keys[NUM_KEYS][ECC_PUBLIC_KEY_SIZE];   // Array for public keys
size_t private_key_lens[NUM_KEYS], public_key_lens[NUM_KEYS];
int current_key_index = 0; // current used key

uint8_t random_buffer[RANDOM_BUFFER_SIZE];         // Random seed for private key generation

uint8_t working_buffer[4096];                      // Working buffer for ECC computations
cmox_ecc_handle_t ecc_ctx;                         // ECC context

// Empfangs- und Sende-Puffer
uint8_t message_buffer[MESSAGE_MAX_LEN];
uint8_t computed_hash[CMOX_SHA256_SIZE];
uint8_t computed_signature[SIGNATURE_SIZE];


typedef struct __attribute__((packed)) {
    char message[LOG_MESSAGE_SIZE];       // Klartextnachricht
    uint8_t hash[32];       // SHA256
} FlashLogEntry;


// Global: holds last known log hash (init with 0 or SHA256("GENESIS"))
uint8_t previous_log_hash[32] = {0};  // initialize to 0 on boot



void flash_log_event_with_data(const char *command, const char *data) {
    RTC_TimeTypeDef sTime;
    RTC_DateTypeDef sDate;
    HAL_RTC_GetTime(&hrtc, &sTime, RTC_FORMAT_BIN);
    HAL_RTC_GetDate(&hrtc, &sDate, RTC_FORMAT_BIN);

    FlashLogEntry entry = {0};

    // Format timestamp
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             2000 + sDate.Year, sDate.Month, sDate.Date,
             sTime.Hours, sTime.Minutes, sTime.Seconds);

    // Format message
    if (data && strlen(data) > 0) {
        snprintf(entry.message, sizeof(entry.message), "[%s] %s | %s", timestamp, command, data);
    } else {
        snprintf(entry.message, sizeof(entry.message), "[%s] %s", timestamp, command);
    }

    // Pad message with 0x00 if needed
    size_t msg_len = strlen(entry.message);
    if (msg_len < sizeof(entry.message)) {
        memset(&entry.message[msg_len], 0x00, sizeof(entry.message) - msg_len);
    }

    // Compute hash
    uint8_t hash_input[32 + sizeof(entry.message)];
    memcpy(hash_input, previous_log_hash, 32);
    memcpy(hash_input + 32, entry.message, sizeof(entry.message));

    cmox_hash_compute(
        CMOX_SHA256_ALGO,
        hash_input, sizeof(hash_input),
        entry.hash, 32,
        NULL
    );
    memcpy(previous_log_hash, entry.hash, 32);

    // Write to flash
    HAL_FLASH_Unlock();
    uint32_t addr = LOG_FLASH_START_ADDR;

    for (int i = 0; i < LOG_MAX_ENTRIES; i++) {
        bool slot_is_blank = true;
        for (int b = 0; b < sizeof(FlashLogEntry); b++) {
            if (*((uint8_t *)(addr + b)) != 0xFF) {
                slot_is_blank = false;
                break;
            }
        }

        if (slot_is_blank) {
            const uint8_t *data_ptr = (const uint8_t *)&entry;
            for (int j = 0; j < sizeof(FlashLogEntry); j += 8) {
                uint64_t word = 0xFFFFFFFFFFFFFFFF;
                size_t remaining = sizeof(FlashLogEntry) - j;
                if (remaining >= 8) {
                    memcpy(&word, data_ptr + j, 8);
                } else {
                    memcpy(&word, data_ptr + j, remaining);
                }
                HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, addr + j, word);
            }
            break;
        }
        addr += sizeof(FlashLogEntry);
    }

    HAL_FLASH_Lock();
}


void flash_log_read(UART_HandleTypeDef *huart) {
    uint32_t addr = LOG_FLASH_START_ADDR;
    FlashLogEntry entry;
    bool found_logs = false;
    FlashLogEntry last_entry;

    for (int i = 0; i < LOG_MAX_ENTRIES; i++) {
        memcpy(&entry, (void *)addr, sizeof(FlashLogEntry));

        // Break if entry is blank
        bool blank = true;
        for (int j = 0; j < sizeof(FlashLogEntry); j++) {
            if (*((uint8_t *)(addr + j)) != 0xFF) {
                blank = false;
                break;
            }
        }
        if (blank) break;

        entry.message[sizeof(entry.message) - 1] = '\0';

        // Print message
        HAL_UART_Transmit(huart, (uint8_t *)"• ", 2, HAL_MAX_DELAY);
        HAL_UART_Transmit(huart, (uint8_t *)entry.message, strlen(entry.message), HAL_MAX_DELAY);
        HAL_UART_Transmit(huart, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);

        memcpy(&last_entry, &entry, sizeof(FlashLogEntry));
        addr += sizeof(FlashLogEntry);
        found_logs = true;
    }

    if (!found_logs) {
        const char *msg = "⚠️ No logs found.\r\n";
        HAL_UART_Transmit(huart, (uint8_t *)msg, strlen(msg), HAL_MAX_DELAY);
    } else {
        // Send final hash only
        char hash_str[65];
        for (int i = 0; i < 32; i++) {
            snprintf(&hash_str[i * 2], 3, "%02X", last_entry.hash[i]);
        }
        HAL_UART_Transmit(huart, (uint8_t *)"\r\nLatest Hash: ", 15, HAL_MAX_DELAY);
        HAL_UART_Transmit(huart, (uint8_t *)hash_str, 64, HAL_MAX_DELAY);
        HAL_UART_Transmit(huart, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);
    }
}


void flash_log_clear(void)
{
    HAL_FLASH_Unlock();

    // Overwrite everything
    for (uint32_t addr = LOG_FLASH_START_ADDR; addr < LOG_FLASH_START_ADDR + LOG_FLASH_PAGE_SIZE; addr += 8) {
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, addr, 0xFFFFFFFFFFFFFFFF);
    }

    FLASH_EraseInitTypeDef erase_config = {
        .TypeErase = FLASH_TYPEERASE_PAGES,
        .Banks = FLASH_BANK_2,
        .Page = FLASH_PAGE_NUMBER,
        .NbPages = 1
    };

    // Then delete
    uint32_t page_error = 0;
    HAL_StatusTypeDef status = HAL_FLASHEx_Erase(&erase_config, &page_error);
    if (status != HAL_OK) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"❌ ERASE FAILED!\r\n", 18, HAL_MAX_DELAY);
        HAL_FLASH_Lock();
        return;
    }




    HAL_FLASH_Lock();

    const char *msg = "✅ Flash log cleared.\r\n";
    HAL_UART_Transmit(&huart2, (uint8_t *)msg, strlen(msg), HAL_MAX_DELAY);

    // Verify again
    bool ok = true;
    for (int i = 0; i < LOG_FLASH_PAGE_SIZE; i++) {
        uint8_t b = *(uint8_t *)(LOG_FLASH_START_ADDR + i);
        if (b != 0xFF) {
            char msg[64];
            snprintf(msg, sizeof(msg), "❗ Residual at +0x%03X = 0x%02X\r\n", i, b);
            HAL_UART_Transmit(&huart2, (uint8_t*)msg, strlen(msg), HAL_MAX_DELAY);
            ok = false;
            break;
        }
    }

    if (ok) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"🧪 Flash verify OK: All 0xFF\r\n", 30, HAL_MAX_DELAY);
    } else {
        HAL_UART_Transmit(&huart2, (uint8_t *)"❗ Flash verify FAILED\r\n", 24, HAL_MAX_DELAY);
    }
}




void generate_random_bytes(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i += 4) {
        uint32_t random_number;

        // Check if the RNG generation was successful
        if (HAL_RNG_GenerateRandomNumber(&hrng, &random_number) != HAL_OK) {
            // ERROR: TRNG failed
            HAL_UART_Transmit(&huart2, (uint8_t *)"ERROR: TRNG failed!\r\n", 21, HAL_MAX_DELAY);
            Error_Handler();  // Halt execution (optional, or return error)
            return;
        }

        // Prevent buffer overflow for remaining bytes
        if (i + 4 <= length) {
            memcpy(&buffer[i], &random_number, sizeof(uint32_t));
        } else {
            memcpy(&buffer[i], &random_number, length - i);
        }
    }
}

void generate_all_keys(void) {
    for (int i = 0; i < NUM_KEYS; i++) {
        cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_SMALL, working_buffer, sizeof(working_buffer));
        generate_random_bytes(random_buffer, RANDOM_BUFFER_SIZE);

        cmox_ecc_retval_t retval;

        retval = cmox_ecdsa_keyGen(
            &ecc_ctx,
            ECC_CURVE_PARAMS,
            random_buffer, RANDOM_BUFFER_SIZE,
            private_keys[i], &private_key_lens[i],
            public_keys[i], &public_key_lens[i]
        );

        if (retval == CMOX_ECC_SUCCESS) {
            // Hash Public Key
            uint8_t pubkey_hash[32];
            cmox_hash_compute(CMOX_SHA256_ALGO, public_keys[i], public_key_lens[i], pubkey_hash, 32, NULL);

            char hex_string[65] = {0};
            for (int j = 0; j < 32; j++) {
                sprintf(&hex_string[j * 2], "%02X", pubkey_hash[j]);
            }

            char cmd[32];
            snprintf(cmd, sizeof(cmd), "GENKEY[%d]", i);
            flash_log_event_with_data(cmd, hex_string);
        }

        char msg[50];
        snprintf(msg, sizeof(msg), "Key[%d] generation %s\r\n", i,
                 (retval == CMOX_ECC_SUCCESS) ? "OK" : "FAILED");
        HAL_UART_Transmit(&huart2, (uint8_t *)msg, strlen(msg), HAL_MAX_DELAY);
    }
}


bool is_current_key_valid(void) {
    return (private_key_lens[current_key_index] == ECC_PRIVATE_KEY_SIZE &&
            public_key_lens[current_key_index] == ECC_PUBLIC_KEY_SIZE);
}


void send_public_key_to_pc(void) {
    if (!is_current_key_valid()) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"No public key to send. Use GENKEY first.\r\n", 45, HAL_MAX_DELAY);
        return;
    }

    HAL_UART_Transmit(&huart2, (uint8_t *)"[PUBKEY]\r\n", 10, HAL_MAX_DELAY); // Marker with newline

    // Send currently selected public key
    HAL_UART_Transmit(&huart2, public_keys[current_key_index], ECC_PUBLIC_KEY_SIZE, HAL_MAX_DELAY);

    HAL_UART_Transmit(&huart2, (uint8_t *)"[ENDKEY]\r\n", 10, HAL_MAX_DELAY); // Marker with newline

    // 🔐 Compute and log hash of the sent public key
    uint8_t pubkey_hash[32];
    cmox_hash_compute(CMOX_SHA256_ALGO,
                      public_keys[current_key_index],
                      ECC_PUBLIC_KEY_SIZE,
                      pubkey_hash,
                      sizeof(pubkey_hash),
                      NULL);

    char hex_string[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(&hex_string[i * 2], "%02X", pubkey_hash[i]);
    }

    char cmd[32];
    snprintf(cmd, sizeof(cmd), "SENDPUB[%d]", current_key_index);
    flash_log_event_with_data(cmd, hex_string);
}


void flush_uart_buffer(void) {
    uint8_t dummy;
    while (HAL_UART_Receive(&huart2, &dummy, 1, 10) == HAL_OK) {} // Leere den Buffer
}

void print_computed_hash(uint8_t *hash, size_t length) {
    char hash_str[65]; // 32 bytes * 2 characters per byte + null terminator

    for (size_t i = 0; i < length; i++) {
        snprintf(&hash_str[i * 2], 3, "%02X", hash[i]);  // Convert to hex string
    }

    // Send the computed hash over UART
    HAL_UART_Transmit(&huart2, (uint8_t *)"Computed Hash: ", 15, HAL_MAX_DELAY);
    HAL_UART_Transmit(&huart2, (uint8_t *)hash_str, strlen(hash_str), HAL_MAX_DELAY);
    HAL_UART_Transmit(&huart2, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);
}

void sign_message() {
	if (!is_current_key_valid()) {
	    HAL_UART_Transmit(&huart2, (uint8_t *)"No valid key available. Use GENKEY first.\r\n", 45, HAL_MAX_DELAY);
	    return;
	}

    cmox_ecc_retval_t retval;
    uint8_t random_data[32];
    size_t computed_size;
    uint8_t received_byte;
    size_t msg_index = 0;
    uint8_t message[MESSAGE_MAX_LEN];

    HAL_UART_Transmit(&huart2, (uint8_t *)"Waiting for message...\r\n", 24, HAL_MAX_DELAY);

    // Read message until we receive [ENDSIGN]
    while (msg_index < MESSAGE_MAX_LEN - 1) {
        HAL_UART_Receive(&huart2, &received_byte, 1, HAL_MAX_DELAY);

        if (received_byte == '[') {
            // Check for the end marker
            uint8_t buffer[8] = {0};
            HAL_UART_Receive(&huart2, buffer, 8, HAL_MAX_DELAY);
            if (strncmp((char *)buffer, "ENDSIGN]", 8) == 0) {
                break;  // Exit the loop
            }
        }

        // Ignore newline and carriage return characters
        if (received_byte != '\r' && received_byte != '\n') {
            message_buffer[msg_index++] = received_byte;
        }
    }

    HAL_UART_Transmit(&huart2, (uint8_t *)"Message Received!\r\n", 19, HAL_MAX_DELAY);

    printf(message_buffer);

    // Compute SHA-256 HASH
    retval = cmox_hash_compute(
        CMOX_SHA256_ALGO,
		message_buffer, msg_index,
        computed_hash,
        CMOX_SHA256_SIZE,
        &computed_size
    );

    if (retval != CMOX_HASH_SUCCESS) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"ERROR: Hashing failed\r\n", 23, HAL_MAX_DELAY);
    } else {
    	print_computed_hash(computed_hash, CMOX_SHA256_SIZE);
    	HAL_UART_Transmit(&huart2, (uint8_t *)"SHA-256 Hash Computed Successfully!\r\n", 38, HAL_MAX_DELAY);
    }

    // Convert hash to hex string for logging
    char hash_hex[65] = {0};
    for (int i = 0; i < CMOX_SHA256_SIZE; i++) {
        sprintf(&hash_hex[i * 2], "%02X", computed_hash[i]);
    }

    // Format log entry
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "SIGN[%d]", current_key_index);
    flash_log_event_with_data(cmd, hash_hex);


    // Initialize ECC context
    //cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_SMALL, working_buffer, sizeof(working_buffer));

    generate_random_bytes(random_buffer, sizeof(random_buffer));  // Fill buffer with randomness

    // Sign the message hash
    retval = cmox_ecdsa_sign(
        &ecc_ctx,
		ECC_CURVE_PARAMS,
        random_buffer, sizeof(random_buffer),
        private_keys[current_key_index], private_key_lens[current_key_index],
        computed_hash, CMOX_SHA256_SIZE,
        computed_signature, &computed_size
    );


    if (retval == CMOX_ECC_SUCCESS) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"✅ STM32 Self Verification SUCCESS\r\n", 36, HAL_MAX_DELAY);
    } else {
        HAL_UART_Transmit(&huart2, (uint8_t *)"❌ STM32 Self Verification FAILED\r\n", 35, HAL_MAX_DELAY);
    }

    // Clean up ECC context
    //cmox_ecc_cleanup(&ecc_ctx);

    // Check if signing was successful
    if (retval != CMOX_ECC_SUCCESS) {
        char *error_msg = "ERROR: Signing failed\r\n";
        HAL_UART_Transmit(&huart2, (uint8_t *)error_msg, strlen(error_msg), HAL_MAX_DELAY);
        return;
    }

    // Send acknowledgment
    HAL_UART_Transmit(&huart2, (uint8_t *)"[SIGN]\r\n", 8, HAL_MAX_DELAY);

    // Send the ECDSA signature (64 bytes)
    HAL_UART_Transmit(&huart2, computed_signature, SIGNATURE_SIZE, HAL_MAX_DELAY);

    // Send end marker
    HAL_UART_Transmit(&huart2, (uint8_t *)"[ENDSIGN]\r\n", 11, HAL_MAX_DELAY);
}

void key_info(void) {
    char buffer[100];

    for (int i = 0; i < NUM_KEYS; i++) {
        int is_valid = (private_key_lens[i] > 0 && public_key_lens[i] > 0);

        if (is_valid) {
            snprintf(buffer, sizeof(buffer), "Key %d (HEX)%s:\r\n",
                     i, (i == current_key_index) ? " [aktiv]" : "");
            HAL_UART_Transmit(&huart2, (uint8_t *)buffer, strlen(buffer), HAL_MAX_DELAY);

            for (int j = 0; j < ECC_PUBLIC_KEY_SIZE; j++) {
                snprintf(buffer, sizeof(buffer), "%02X", public_keys[i][j]);
                HAL_UART_Transmit(&huart2, (uint8_t *)buffer, 2, HAL_MAX_DELAY);

                if ((j + 1) % 32 == 0)
                    HAL_UART_Transmit(&huart2, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);
            }

        } else {
            snprintf(buffer, sizeof(buffer), "Key %d: ❌ empty\r\n", i);
            HAL_UART_Transmit(&huart2, (uint8_t *)buffer, strlen(buffer), HAL_MAX_DELAY);
        }
    }
}



void delete_all_keys(void) {
    for (int i = 0; i < NUM_KEYS; i++) {
        memset(private_keys[i], 0, ECC_PRIVATE_KEY_SIZE);
        memset(public_keys[i], 0, ECC_PUBLIC_KEY_SIZE);
        private_key_lens[i] = 0;
        public_key_lens[i] = 0;
    }
    current_key_index = 0;

    HAL_UART_Transmit(&huart2, (uint8_t *)"All keys deleted. Reset to key index 0.\r\n", 42, HAL_MAX_DELAY);
}

void set_rtc_from_command(char *cmd, UART_HandleTypeDef *huart)
{
    int year, month, day, hour, min, sec;

    // Expecting format: "SETRTC YYYY-MM-DD HH:MM:SS"
    if (sscanf(cmd, "SETRTC %d-%d-%d %d:%d:%d",
               &year, &month, &day, &hour, &min, &sec) == 6)
    {
        RTC_TimeTypeDef sTime = {0};
        RTC_DateTypeDef sDate = {0};

        sTime.Hours   = hour;
        sTime.Minutes = min;
        sTime.Seconds = sec;

        sDate.Year  = year - 2000;  // RTC stores 0–99 (for 2000–2099)
        sDate.Month = month;
        sDate.Date  = day;
        sDate.WeekDay = RTC_WEEKDAY_MONDAY;

        if (HAL_RTC_SetTime(&hrtc, &sTime, RTC_FORMAT_BIN) == HAL_OK &&
            HAL_RTC_SetDate(&hrtc, &sDate, RTC_FORMAT_BIN) == HAL_OK)
        {
            const char *ok = "✅ RTC updated.\r\n";
            HAL_UART_Transmit(huart, (uint8_t*)ok, strlen(ok), HAL_MAX_DELAY);
        }
        else
        {
            const char *fail = "❌ RTC update failed.\r\n";
            HAL_UART_Transmit(huart, (uint8_t*)fail, strlen(fail), HAL_MAX_DELAY);
        }
    }
    else
    {
        const char *syntax = "❌ Invalid format. Use: SETRTC YYYY-MM-DD HH:MM:SS\r\n";
        HAL_UART_Transmit(huart, (uint8_t*)syntax, strlen(syntax), HAL_MAX_DELAY);
    }
}

void process_command(void) {
    char command_buffer[64] = {0};  // Buffer for command
    size_t index = 0;

    flush_uart_buffer();  // Clear UART buffer

    // Read command until newline ('\n') is received
    while (index < sizeof(command_buffer) - 1) {
        uint8_t byte;
        HAL_UART_Receive(&huart2, &byte, 1, HAL_MAX_DELAY);

        if (byte == '\r' || byte == '\n') {  // Accept both '\n' and '\r\n' {
            command_buffer[index] = '\0';
            break;
        }
        command_buffer[index++] = byte;
    }

    HAL_UART_Transmit(&huart2, (uint8_t *)"\nReceived: ", 11, HAL_MAX_DELAY);
    HAL_UART_Transmit(&huart2, (uint8_t *)command_buffer, strlen(command_buffer), HAL_MAX_DELAY);
    HAL_UART_Transmit(&huart2, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);

    // Check command and execute corresponding function
    if (strcmp(command_buffer, "GENKEY") == 0) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"Generating new key pairs...\r\n", 29, HAL_MAX_DELAY);
        generate_all_keys();
    }
    else if (strcmp(command_buffer, "SENDPUB") == 0) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"Sending public key...\r\n", 24, HAL_MAX_DELAY);
        send_public_key_to_pc();
    }
    else if (strcmp(command_buffer, "SIGN") == 0) {
        //HAL_UART_Transmit(&huart2, (uint8_t *)"Waiting for message to sign...\r\n", 32, HAL_MAX_DELAY);
        sign_message();
    }
    else if (strcmp(command_buffer, "DELKEYS") == 0) {
        delete_all_keys();
    }
    else if (strcmp(command_buffer, "KEYINFO") == 0) {
        key_info();
    }
    else if (strcmp(command_buffer, "GETLOGS") == 0) {
        flash_log_read(&huart2);
    }
    else if (strncmp((char*)command_buffer, "CLEARLOGS", 9) == 0) {
        flash_log_clear();
    }
    else if (strncmp((char*)command_buffer, "SETRTC", 6) == 0) {
        set_rtc_from_command((char*)command_buffer, &huart2);
    }


    else if (strncmp(command_buffer, "USEKEY", 6) == 0) {
        int key_idx = atoi(&command_buffer[6]);
        if (key_idx >= 0 && key_idx < NUM_KEYS) {
            current_key_index = key_idx;
            char msg[40];
            snprintf(msg, sizeof(msg), "Using key index %d\r\n", current_key_index);
            HAL_UART_Transmit(&huart2, (uint8_t *)msg, strlen(msg), HAL_MAX_DELAY);
        } else {
            HAL_UART_Transmit(&huart2, (uint8_t *)"Invalid key index!\r\n", 21, HAL_MAX_DELAY);
        }
    }

    else if (strcmp(command_buffer, "HELP") == 0) {
        HAL_UART_Transmit(&huart2, (uint8_t *)
            "\nCommands:\n"
            "GENKEY  - Generate ECDSA key pair\r\n"
            "SENDPUB - Send public key\r\n"
            "SIGN    - Sign a received message\r\n"
            "HELP    - Show this menu\r\n",
            100, HAL_MAX_DELAY);
    }
    else {
        HAL_UART_Transmit(&huart2, (uint8_t *)"Unknown command. Type HELP for list.\r\n", 38, HAL_MAX_DELAY);
    }
}




/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART2_UART_Init();
  MX_CRC_Init();
  MX_RNG_Init();
  MX_RTC_Init();
  /* USER CODE BEGIN 2 */


  const char *welcome_message = "\r\nWelcome to HSM Firmware on STM32G474RE\r\n";
  HAL_UART_Transmit(&huart2, (uint8_t *)welcome_message, strlen(welcome_message), HAL_MAX_DELAY);



  /* generate ecc key pair
  generate_ecdsa_key_pair();

  // send public key to pc
  send_public_key_to_pc();

  //get sign request
  process_sign_request();

  */
  //  cmox_ecc_cleanup(&Ecc_Ctx);
  // wait to receive message (to get signed)
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

  /* Buffer and input control variables */


  while (1)
  {
	  /*
	  printf("test\n");
	  HAL_Delay(1000);*/
	  //flash_log_event_with_data("BOOT", "OK");
	  process_command();
	  HAL_UART_Transmit(&huart2, (uint8_t *)"\nWaiting for command...\r\n", 26, HAL_MAX_DELAY);

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  LL_FLASH_SetLatency(LL_FLASH_LATENCY_3);
  while(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_3)
  {
  }
  LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);
  LL_RCC_HSE_Enable();
   /* Wait till HSE is ready */
  while(LL_RCC_HSE_IsReady() != 1)
  {
  }

  LL_RCC_HSI_Enable();
   /* Wait till HSI is ready */
  while(LL_RCC_HSI_IsReady() != 1)
  {
  }

  LL_RCC_HSI_SetCalibTrimming(64);
  LL_PWR_EnableBkUpAccess();
  LL_RCC_PLL_ConfigDomain_SYS(LL_RCC_PLLSOURCE_HSI, LL_RCC_PLLM_DIV_1, 12, LL_RCC_PLLR_DIV_2);
  LL_RCC_PLL_ConfigDomain_48M(LL_RCC_PLLSOURCE_HSI, LL_RCC_PLLM_DIV_1, 12, LL_RCC_PLLQ_DIV_4);
  LL_RCC_PLL_EnableDomain_SYS();
  LL_RCC_PLL_EnableDomain_48M();
  LL_RCC_PLL_Enable();
   /* Wait till PLL is ready */
  while(LL_RCC_PLL_IsReady() != 1)
  {
  }

  LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_PLL);
  LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_2);
   /* Wait till System clock is ready */
  while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_PLL)
  {
  }

  /* Insure 1us transition state at intermediate medium speed clock*/
  for (__IO uint32_t i = (170 >> 1); i !=0; i--);

  /* Set AHB prescaler*/
  LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);
  LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);
  LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_1);
  LL_SetSystemCoreClock(96000000);

   /* Update the time base */
  if (HAL_InitTick (TICK_INT_PRIORITY) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */
/**
  * @brief  Retargets the C library printf function to the USART.
  *   None
  * @retval None
  */
PUTCHAR_PROTOTYPE
{
  /* Place your implementation of fputc here */
  /* e.g. write a character to the USART1 and Loop until the end of transmission */
  HAL_UART_Transmit(&huart2, (uint8_t *)&ch, 1, 0xFFFF);

  return ch;
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
