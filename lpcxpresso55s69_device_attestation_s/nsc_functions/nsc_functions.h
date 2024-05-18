/*
 * FreeRTOS Pre-Release V1.0.0
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#ifndef __NSC_FUNCTIONS_H__
#define __NSC_FUNCTIONS_H__

#include <stdint.h>

/* Trustzone config. */
#include "tzm_config.h"

/* FreeRTOS includes. */
#include "secure_port_macros.h"

#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_power.h"
#include "fsl_debug_console.h"

// SDK Included Files
#include "board.h"
#include "qcom_api.h"
#include "wlan_qcom.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MAX_STRING_LENGTH 0x400

// Key for computing hmac.
static uint8_t key1[32] =   { 0x10, 0x12, 0x9f, 0x46, 0x21, 0xb4, 0x79, 0xe8,
                            0x4d, 0x0d, 0x16, 0x88, 0x23, 0xf1, 0xa2, 0xd4,
                            0xdc, 0x85, 0x52, 0x5a, 0xe8, 0x79, 0xe5, 0x86,
                            0x02, 0x73, 0x91, 0x6b, 0x91, 0xc7, 0x24, 0xe9 };
static uint8_t key2[32] = { 0x10, 0x12, 0x9f, 0xe8, 0x4d, 0x0d, 0x16, 0x88,
							0x23, 0xf1, 0xa2, 0xd4, 0xdc, 0x85, 0x52, 0x5a,
							0xe8, 0x79, 0xe5, 0x86, 0x46, 0x21, 0xb4, 0x79,
	                       0x02, 0x73, 0x91, 0x6b, 0x91, 0xc7, 0x24, 0xe9 };
static uint8_t key3[32] = { 0x10, 0x12, 0x9f, 0x91, 0xc7, 0x24, 0xe9, 0x46,
							0x21, 0xb4, 0x79, 0xe8, 0x4d, 0x0d, 0x16, 0x88,
							0x23, 0xf1, 0xa2, 0xd4, 0xdc, 0x85, 0x52, 0x5a,
							0xe8, 0x79, 0xe5, 0x86, 0x02, 0x73, 0x91, 0x6b };


static uint32_t reset_counter = 0;
#define RESET_COUNTER_LEN 32
static uint32_t local_counter = 0;
#define COUNTER_WINDOW_LEN 5
static uint32_t counter_windows[COUNTER_WINDOW_LEN] = {0};
static uint32_t start_timestamp = 0;
static uint32_t start_seconds = 0;

/**
 * @brief Callback function pointer definition.
 */
typedef void (*Callback_t)(void);

/**
 * @brief Invokes the supplied callback which is on the non-secure side.
 *
 * Returns a number which is one more than the value returned in previous
 * invocation of this function. Initial invocation returns 1.
 *
 * @param pxCallback[in] The callback to invoke.
 *
 * @return A number which is one more than the value returned in previous
 * invocation of this function.
 */
uint32_t NSCFunction(Callback_t pxCallback);

/**
 * @brief Toggles the on-board green LED.
 */
void vToggleGreenLED(void);

/**
 * @brief Toggles the on-board blue LED.
 */
void vToggleBlueLED(void);

/**
 * @brief Turn on the on-board blue LED.
 */
void vTurnOnBlueLED(void);
void vTurnOnGreenLED(void);
/**
 * @brief Turn off the on-board blue LED.
 */
void vTurnOffBlueLED(void);

void vTurnOffGreenLED(void);

/**
 * @brief Return the secure side SystemCoreClock.
 */
uint32_t getSystemCoreClock(void);

/**
 * @brief Run the attestation code.
 */
uint8_t check_ticket(uint8_t *resp, uint8_t *message, uint8_t *ticket);
void run_attestation(uint8_t *resp,  uint8_t *session_key, uint8_t *saddr, uint32_t mem_size);
void calculate_session_key(uint8_t *key, uint8_t *message, uint8_t messageLen);
void set_start_time_stamp(uint32_t time_stamp);
void set_local_counter(uint32_t response_counter);
void set_counter_window(uint32_t response_counter);
uint32_t get_current_timer_value();
uint8_t check_counter_value(uint8_t *counter_value);
uint8_t check_ticket_lifetime(uint32_t lifetime);
uint8_t check_time_stamp_hmac(uint8_t *resp, uint8_t *session_key, uint8_t *time_stamp, uint8_t *time_stamp_mac);
uint8_t check_time_stamp(uint32_t time_stamp);
uint8_t check_reset_counter(uint32_t response_reset_counter);
uint8_t check_local_counter(uint32_t request_local_counter);
uint8_t check_auth_is(uint8_t *resp, uint8_t *message, uint8_t *authIs, uint8_t messageLen);
void start_timer();
void prepare_update_request(uint8_t* sync_val_update_request);
size_t convert_hex(uint8_t *dest, size_t count, const char *src);
size_t convert_bytes(char* dest, size_t count, const uint8_t *src);
void get_memory_digest(const char *msg, size_t msg_len, unsigned char *resp);
#endif /* __NSC_FUNCTIONS_H__ */
