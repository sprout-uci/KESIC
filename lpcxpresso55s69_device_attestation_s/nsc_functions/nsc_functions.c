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

/* CMSE includes. */
#include <arm_cmse.h>

/* NSC functions includes. */
#include "nsc_functions.h"
#include "fsl_rtc.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* Board specific includes. */
#include "board.h"

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

/**
 * @brief Counter returned from NSCFunction.
 */
static uint32_t ulSecureCounter = 0;

/**
 * @brief LED port and pins.
 */
#define LED_PORT      BOARD_LED_BLUE_GPIO_PORT
#define GREEN_LED_PIN BOARD_LED_GREEN_GPIO_PIN
#define BLUE_LED_PIN  BOARD_LED_BLUE_GPIO_PIN

/**
 * @brief typedef for non-secure callback.
 */
#if defined(__IAR_SYSTEMS_ICC__)
typedef __cmse_nonsecure_call void (*NonSecureCallback_t)(void);
#else
typedef void (*NonSecureCallback_t)(void) __attribute__((cmse_nonsecure_call));
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/
/* strnlen function implementation for arm compiler */
#if defined(__arm__)
size_t strnlen(const char *s, size_t maxLength)
{
    size_t length = 0;
    while ((length <= maxLength) && (*s))
    {
        s++;
        length++;
    }
    return length;
}
#endif

/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    uint32_t
    NSCFunction(Callback_t pxCallback)
{
    NonSecureCallback_t pxNonSecureCallback;

    /* Return function pointer with cleared LSB. */
    pxNonSecureCallback = (NonSecureCallback_t)cmse_nsfptr_create(pxCallback);

    /* Invoke the supplied callback. */
    pxNonSecureCallback();

    /* Increment the secure side counter. */
    ulSecureCounter += 1;

    /* Return the secure side counter. */
    return ulSecureCounter;
}
/*-----------------------------------------------------------*/


#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vToggleGreenLED(void)
{
    /* Toggle the on-board green LED. */
    GPIO_PortToggle(GPIO, LED_PORT, (1U << GREEN_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vToggleBlueLED()
{
    /* Toggle the on-board blue LED. */
    GPIO_PortToggle(GPIO, LED_PORT, (1U << BLUE_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vTurnOnBlueLED(void)
{
    /* Turn on the on-board blue LED. */
	GPIO_PortClear(GPIO, LED_PORT, (1U << BLUE_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vTurnOffBlueLED()
{
    /* Turn off the on-board blue LED. */
	GPIO_PortSet(GPIO, LED_PORT, (1U << BLUE_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vTurnOnGreenLED(void)
{
    /* Turn on the on-board blue LED. */
	GPIO_PortClear(GPIO, LED_PORT, (1U << GREEN_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
    vTurnOffGreenLED()
{
    /* Turn off the on-board blue LED. */
	GPIO_PortSet(GPIO, LED_PORT, (1U << GREEN_LED_PIN));
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    uint32_t
    getSystemCoreClock(void)
{
    /* Return the secure side SystemCoreClock. */
    return SystemCoreClock;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_time_stamp_hmac(uint8_t *resp, uint8_t *session_key, uint8_t *time_stamp, uint8_t *time_stamp_mac)
{
	hmac256((uint8_t*) session_key, (uint32_t) 32, (uint8_t*) time_stamp, (uint32_t) 16, (uint8_t*) resp);
	if(memcmp((uint8_t*) resp, (uint8_t*) time_stamp_mac, 32) != 0){
		return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void calculate_session_key(uint8_t *key, uint8_t *message, uint8_t messageLen)
{
	/* Derive a one-time challenge based key. */
	hmac256((uint8_t*) key2, (uint32_t) 32, (uint8_t*) message, messageLen, (uint8_t*) key);
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void set_start_time_stamp(uint32_t time_stamp)
{
	start_timestamp = time_stamp;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void set_local_counter(uint32_t response_counter)
{
	local_counter = response_counter;
}
#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void set_counter_window(uint32_t response_counter)
{
	int diff = response_counter - local_counter;
	if(diff<0){
		diff=diff*(-1);
	}
	counter_windows[diff]=1;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_ticket(uint8_t *resp, uint8_t *message, uint8_t *ticket)
{
	hmac256((uint8_t*) key1, (uint32_t) 32, (uint8_t*) message, (uint32_t) 28, (uint8_t*) resp);
	if(memcmp((uint8_t*) resp, (uint8_t*) ticket, 32) != 0){
		return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_auth_is(uint8_t *resp, uint8_t *message, uint8_t *authIs, uint8_t messageLen)
{
	hmac256((uint8_t*) key3, (uint32_t) 32, (uint8_t*) message, messageLen, (uint8_t*) resp);
	if(memcmp((uint8_t*) resp, (uint8_t*) authIs, 32) != 0){
		return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void start_timer()
{
    /* Init RTC */
    RTC_Init(RTC);
    /* Start the RTC time counter */
    RTC_StartTimer(RTC);
    start_seconds = RTC->COUNT;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint32_t get_current_timer_value()
{
	uint32_t currSeconds = RTC->COUNT-start_seconds;
	return currSeconds;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
void prepare_update_request(uint8_t* sync_val_update_request)
{
	reset_counter += 1;
	char reset_counter_str[33];
	sprintf(reset_counter_str, "%032d", reset_counter);
	uint8_t reset_counter_bytes[16] = {0};
	convert_hex(reset_counter_bytes, 16, reset_counter_str);
	int offset = 4;
	memcpy((uint8_t*) sync_val_update_request+offset, (uint8_t*) reset_counter_bytes, 16);
	offset += 16;
	uint8_t resp[32] = {0};
	hmac256((uint8_t*) key3, (uint32_t) 32, (uint8_t*) sync_val_update_request, (uint32_t) 20, (uint8_t*) resp);
	memcpy((uint8_t*) sync_val_update_request+offset, (uint8_t*) resp, (uint32_t) 32);
}
/*-----------------------------------------------------------*/


#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_ticket_lifetime(uint32_t lifetime)
{
	uint32_t currSeconds = RTC->COUNT-start_seconds;
	uint32_t currActualTime = start_timestamp + currSeconds;
	if (currActualTime>lifetime){
			return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_time_stamp(uint32_t time_stamp)
{
	uint32_t currSeconds = RTC->COUNT-start_seconds;
	uint32_t currActualTime = start_timestamp + currSeconds;
	int timeDiff = currActualTime - time_stamp;
	if(timeDiff<0){
		timeDiff = timeDiff*(-1);
	}
	if (timeDiff>10){
		return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_reset_counter(uint32_t response_reset_counter)
{
	if (response_reset_counter != reset_counter){
			return -1;
	}
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
uint8_t check_local_counter(uint32_t request_local_counter)
{
	int diff = request_local_counter - local_counter;
	if(diff<0){
		diff=diff*(-1);
	}
	if(diff>=COUNTER_WINDOW_LEN||counter_windows[diff]==1){
			return -1;
	}
	counter_windows[diff]=1;
	return 0;
}
/*-----------------------------------------------------------*/

#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
	run_attestation(uint8_t *resp, uint8_t *session_key, uint8_t *saddr, uint32_t mem_size)
{
	mbedtls_sha256((uint8_t*)saddr, mem_size, (uint8_t*) resp, 0);
	hmac256((uint8_t*) session_key, (uint32_t) 32, (uint8_t*)resp, 32, (uint8_t*) resp);
}
/*-----------------------------------------------------------*/

size_t convert_hex(uint8_t *dest, size_t count, const char *src) {
    size_t i;
    int value;
    for (i = 0; i < count && sscanf(src + i * 2, "%2x", &value) == 1; i++) {
		int ret = sscanf(src + i * 2, "%2x", &value);
        dest[i] = value;
    }
    return i;
}

size_t convert_bytes(char* dest, size_t count, const uint8_t *src) {
	int i;
	for (i = 0; i < count; i++)
	{
		dest += sprintf(dest, "%02X", src[i]);
	}
	return i;
}
#if defined(__IAR_SYSTEMS_ICC__)
__cmse_nonsecure_entry
#else
__attribute__((cmse_nonsecure_entry))
#endif
    void
 get_memory_digest(const char *msg, size_t msg_len, unsigned char *resp){
	mbedtls_sha256((uint8_t*)msg, msg_len, (uint8_t*) resp, 0);
}
void hmac256(const char *key, size_t key_len, const char *msg, size_t msg_len, unsigned char *out)
{
	const mbedtls_md_type_t alg = MBEDTLS_MD_SHA256;
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
	mbedtls_md_setup(&ctx, info, 1);
	mbedtls_md_hmac_starts(&ctx, key, key_len);
	mbedtls_md_hmac_update(&ctx, msg, msg_len);
	mbedtls_md_hmac_finish(&ctx, out);
}
/*-----------------------------------------------------------*/
