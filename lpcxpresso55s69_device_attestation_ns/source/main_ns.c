/*
 * Copyright (c) 2013 - 2014, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

///////////////////////////////////////////////////////////////////////////////
//  Includes
///////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Non-Secure callable functions. */
#include "nsc_functions.h"

// SDK Included Files
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_power.h"
#include "qcom_api.h"
#include "wlan_qcom.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define BOARD_LED_PORT BOARD_LED_GREEN_GPIO_PORT
#define BOARD_LED_PIN BOARD_LED_GREEN_GPIO_PIN


/* Length of FLASH 1 with NS-User privilege */
#define MEM_SIZE 	131976
/* Memory location to attest. */
static unsigned long saddr = 0x30000;	/* Start of FLASH 1 with NS-User privilege */

static uint8_t counter_update_flag = 0;
static uint8_t timestamp_update_flag = 0;

#if defined(__ARMCC_VERSION)
/* Externs needed by MPU setup code.
 * Must match the memory map as specified
 * in scatter file. */
/* Privileged flash. */
extern unsigned int Image$$ER_priv_func$$Base[];
extern unsigned int Image$$ER_priv_func$$Limit[];

extern unsigned int Image$$ER_sys_calls$$Base[];
extern unsigned int Image$$ER_sys_calls$$Limit[];

extern unsigned int Image$$ER_m_text$$Base[];
extern unsigned int Image$$ER_m_text$$Limit[];

extern unsigned int Image$$RW_priv_data$$Base[];
extern unsigned int Image$$RW_priv_data$$Limit[];

const uint32_t *__privileged_functions_start__ = (uint32_t *)Image$$ER_priv_func$$Base;
const uint32_t *__privileged_functions_end__ =
    (uint32_t *)Image$$ER_priv_func$$Limit; /* Last address in privileged Flash region. */

/* Flash containing system calls. */
const uint32_t *__syscalls_flash_start__ = (uint32_t *)Image$$ER_sys_calls$$Base;
const uint32_t *__syscalls_flash_end__ =
    (uint32_t *)Image$$ER_sys_calls$$Limit; /* Last address in Flash region containing system calls. */

/* Unprivileged flash. Note that the section containing
 * system calls is unprivilged so that unprivleged tasks
 * can make system calls. */
const uint32_t *__unprivileged_flash_start__ = (uint32_t *)Image$$ER_sys_calls$$Limit;
const uint32_t *__unprivileged_flash_end__ =
    (uint32_t *)Image$$ER_m_text$$Limit; /* Last address in un-privileged Flash region. */

/* 512 bytes (0x200) of RAM starting at 0x30008000 is
 * priviledged access only. This contains kernel data. */
const uint32_t *__privileged_sram_start__ = (uint32_t *)Image$$RW_priv_data$$Base;
const uint32_t *__privileged_sram_end__ = (uint32_t *)Image$$RW_priv_data$$Limit; /* Last address in privileged RAM. */

#endif
/*-----------------------------------------------------------*/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/**
 * @brief Creates all the tasks for this demo.
 */
static void prvCreateTasks(void);

/**
 * @brief Stack overflow hook.
 */
void vApplicationStackOverflowHook(TaskHandle_t xTask, signed char *pcTaskName);
/*-----------------------------------------------------------*/

/*******************************************************************************
 * Code
 ******************************************************************************/

/* WiFi and device attestation code */

// 0 is the highest priority and priority 15 is the lowest priority
const int TASK_MAIN_PRIO       = configMAX_PRIORITIES - 3;
const int TASK_MAIN_STACK_SIZE = 800;

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

// Hardwired SSID, passphrase of AP to connect to
#define AP_SSID 		"wifi_network_name"
#define AP_PASSPHRASE 	"wifi_network_password"
#define PORT_NUM 9000
#define LED_ON_CMD 		"01"
#define LED_OFF_CMD 	"00"
#define ATTEST_CMD 	"11"
#define COMMAND_LEN 2
#define CLIENT_ID_LEN 8
#define CLIENT_INTERFACE_LEN 8
#define COUNTER_LEN 32
#define CHALLANGE_LEN 32
#define RESET_COUNTER_LEN 32
#define TICKET_LIFETIME_LEN 32
#define TIME_STAMP_LEN 32
#define TICKET_LEN 64
#define TIME_HMAC_LEN 64
#define SYNC_REQUEST_LEN 72
#define IoT_ID "00000001"
#define IoT_ID_NORDIC "00000002"
#define IoT_ID_LEN 8
#define IS_ID_LEN 8
#define IS_ID "10110010"
#define AUTH_IS_LEN 64

QCOM_SSID g_ssid             = {.ssid = (AP_SSID)};
QCOM_PASSPHRASE g_passphrase = {.passphrase = (AP_PASSPHRASE)};

WLAN_AUTH_MODE g_auth    = WLAN_AUTH_WPA2_PSK;
WLAN_CRYPT_TYPE g_cipher = WLAN_CRYPT_AES_CRYPT;

extern int numIrqs;
extern int initTime;


// ============================================================================
// Main
// ============================================================================

size_t convert_hex(uint8_t *dest, size_t count, const char *src) {
    size_t i;
    int value;
    for (i = 0; i < count && sscanf(src + i * 2, "%2x", &value) == 1; i++) {
	//for (i = 0; i < count; i++) {
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

static void print_version(void)
{
    ATH_VERSION_STR verstr;

    int res = qcom_get_versionstr(&verstr);
    if (A_OK == res)
    {
        PRINTF("Host version:      %s\r\n", verstr.host_ver);
        PRINTF("Target version:    %s\r\n", verstr.target_ver);
        PRINTF("Firmware version:  %s\r\n", verstr.wlan_ver);
        PRINTF("Interface version: %s\r\n", verstr.abi_ver);
    }
    else
    {
        PRINTF("ERROR: Failed to get QCA400X version information\r\n");
    }
}

/* Check the received command string. */
int checkCommand(char *recvStr, char *command)
{
	if(strstr(recvStr, command) != NULL){
		return 0;
	}
	return -1;
}

void processMessageCounter(char *recvStr){
	/* Extract the command, client id, client interface and ticket. */
	char *commandStr = custom_alloc(COMMAND_LEN);
	char *clientIdStr = custom_alloc(CLIENT_ID_LEN);
	char *clientInterfaceStr = custom_alloc(CLIENT_INTERFACE_LEN);
	char *counterIoTStr = custom_alloc(COUNTER_LEN);
	char *ticketIoTStr = custom_alloc(TICKET_LEN);

	memcpy(commandStr, recvStr, COMMAND_LEN);
	int offset = COMMAND_LEN;
	memcpy(clientIdStr, recvStr + offset, CLIENT_ID_LEN);
	offset += CLIENT_ID_LEN;
	memcpy(clientInterfaceStr, recvStr + offset, CLIENT_INTERFACE_LEN);
	offset += CLIENT_INTERFACE_LEN;
	memcpy(counterIoTStr, recvStr + offset, COUNTER_LEN);
	offset += COUNTER_LEN;
	memcpy(ticketIoTStr, recvStr + offset, TICKET_LEN);

	// check time stamp value
	uint32_t counterVal = atoi(counterIoTStr);
	uint8_t checkCounterResult = check_local_counter(counterVal);
	if(checkCounterResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 17, "%s", "Invalid Counter!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}
	char *replyStr = custom_alloc(TICKET_LEN+1);
	char full_message[57];
	snprintf(full_message, sizeof(full_message), "%s%s%s%s", clientIdStr, clientInterfaceStr, counterIoTStr, IoT_ID_NORDIC);
	uint8_t message_bytes[28] = {0};
	convert_hex(message_bytes, 28, full_message);
	uint8_t session_key[32] = {0};
	calculate_session_key((uint8_t*) session_key, (uint8_t*) message_bytes, 28);
	uint8_t resp[32] = {0};
	// check ticket
	uint8_t ticketIoT[32] = {0};
	convert_hex(ticketIoT, 32, ticketIoTStr);

	int checkTicketResult = check_ticket((uint8_t*) resp, (uint8_t*) message_bytes, (uint8_t*) ticketIoT);
	if(checkTicketResult==0){
		/* Check for "turn_on" command */
		if (checkCommand(commandStr, (char*) LED_ON_CMD) == 0)
		{
			vTurnOnBlueLED();
			char *returnMessage = custom_alloc(16);
			snprintf(returnMessage, 16, "%s", "Light turned on");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
		/* Check for "turn_off" command */
		else if (checkCommand(commandStr, (char*) LED_OFF_CMD) == 0)
		{
			vTurnOffBlueLED();
			char *returnMessage = custom_alloc(17);
			snprintf(returnMessage, 17, "%s", "Light turned off");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
		else
		{
			char *returnMessage = custom_alloc(15);
			snprintf(returnMessage, 15, "%s", "Invalid Command");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
	}
	else{
		char *returnMessage = custom_alloc(14);
		snprintf(returnMessage, 14, "%s", "Invalid Ticket");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
	}
	free(replyStr);
}

void processMessageTimer(char *recvStr){
	char *commandStr = custom_alloc(COMMAND_LEN);
	char *clientIdStr = custom_alloc(CLIENT_ID_LEN);
	char *clientInterfaceStr = custom_alloc(CLIENT_INTERFACE_LEN);
	char *ticketLifetimeStr = custom_alloc(TICKET_LIFETIME_LEN);
	char *ticketIoTStr = custom_alloc(TICKET_LEN);
	char *timeStampStr = custom_alloc(TIME_STAMP_LEN);
	char *timeHmacStr = custom_alloc(TIME_HMAC_LEN);

	memcpy(commandStr, recvStr, COMMAND_LEN);
	int offset = COMMAND_LEN;
	memcpy(clientIdStr, recvStr + offset, CLIENT_ID_LEN);
	offset += CLIENT_ID_LEN;
	memcpy(clientInterfaceStr, recvStr + offset, CLIENT_INTERFACE_LEN);
	offset += CLIENT_INTERFACE_LEN;
	memcpy(ticketLifetimeStr, recvStr + offset, TICKET_LIFETIME_LEN);
	offset += TICKET_LIFETIME_LEN;
	memcpy(ticketIoTStr, recvStr + offset, TICKET_LEN);
	offset += TICKET_LEN;
	memcpy(timeStampStr, recvStr + offset, TIME_STAMP_LEN);
	offset += TIME_STAMP_LEN;
	memcpy(timeHmacStr, recvStr + offset, TIME_HMAC_LEN);

	// check time stamp value
	uint32_t timeStampVal = atoi(timeStampStr);
	uint8_t checktimeStampResult = check_time_stamp(timeStampVal);
	if(checktimeStampResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 15, "%s", "Invalid Request");
		int length = strlen(returnMessage);

		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}
	char *replyStr = custom_alloc(TICKET_LEN+1);
	char full_message[57];
	snprintf(full_message, sizeof(full_message), "%s%s%s%s", clientIdStr, clientInterfaceStr, ticketLifetimeStr, IoT_ID);
	uint8_t message_bytes[28] = {0};
	convert_hex(message_bytes, 28, full_message);
	uint8_t session_key[32] = {0};
	calculate_session_key((uint8_t*) session_key, (uint8_t*) message_bytes, 28);
	//check time stamp hmac
	uint8_t time_stamp_bytes[16] = {0};
	convert_hex(time_stamp_bytes, 16, timeStampStr);
	uint8_t time_stamp_hmac_bytes[32] = {0};
	convert_hex(time_stamp_hmac_bytes, 32, timeHmacStr);

	uint8_t resp[32] = {0};
	uint8_t checkTimeStampMacResult = check_time_stamp_hmac((uint8_t*) resp, (uint8_t*) session_key, (uint8_t*) time_stamp_bytes, (uint8_t*) time_stamp_hmac_bytes);
	convert_bytes(replyStr, 32, resp);
	if(checkTimeStampMacResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 17, "%s", "Invalid Request");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}

	// check life time value
	uint32_t ticketLifeTimeVal = atoi(ticketLifetimeStr);
	uint8_t timeHmac[32] = {0};
	convert_hex(timeHmac, 32, timeHmacStr);
	//check ticket life time
	uint8_t checkLifetimeResult = check_ticket_lifetime(ticketLifeTimeVal);
	if(checkLifetimeResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 15, "%s", "Ticket Expired");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}

	// check ticket
	uint8_t ticketIoT[32] = {0};
	convert_hex(ticketIoT, 32, ticketIoTStr);

	int checkTicketResult = check_ticket((uint8_t*) resp, (uint8_t*) message_bytes, (uint8_t*) ticketIoT);
	convert_bytes(replyStr, 32, resp);
	if(checkTicketResult==0){
		        	/* Check for "turn_on" command; call NSC function. */
		if (checkCommand(commandStr, (char*) LED_ON_CMD) == 0)
		{
			vTurnOnBlueLED();
			char *returnMessage = custom_alloc(16);
			snprintf(returnMessage, 16, "%s", "Light turned on");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
		/* Check for "turn_off" command*/
		else if (checkCommand(commandStr, (char*) LED_OFF_CMD) == 0)
		{
			vTurnOffBlueLED();
			char *returnMessage = custom_alloc(17);
			snprintf(returnMessage, 17, "%s", "Light turned off");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
		/* Check for "attest" command */
		else if (checkCommand(commandStr, (char*) ATTEST_CMD) == 0)
		{
			run_attestation((uint8_t*) resp, (uint8_t*) session_key, (uint8_t*) saddr, MEM_SIZE);
			convert_bytes(replyStr, 32, resp);
			udpSend(replyStr, TICKET_LEN);
		}
		else
		{
			char *returnMessage = custom_alloc(15);
			snprintf(returnMessage, 15, "%s", "Invalid Command");
			int length = strlen(returnMessage);
			udpSend(returnMessage, length);
			free(returnMessage);
		}
	}
	else{
		char *returnMessage = custom_alloc(14);
		snprintf(returnMessage, 14, "%s", "Invalid Ticket");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
	}
	free(replyStr);
}

int updateCounterValue(){
	uint8_t sync_val_update_request[52] = {0};
	uint8_t iot_id_bytes[4] = {0};
	convert_hex(iot_id_bytes, 4, IoT_ID_NORDIC);
	memcpy((uint8_t*) sync_val_update_request, (uint8_t*) iot_id_bytes, 4);
	prepare_update_request((uint8_t*) sync_val_update_request);
	char *requestStr = custom_alloc(105);
	convert_bytes(requestStr, 52, sync_val_update_request);

	char *firstResponse = custom_alloc(104);
	firstResponse = udpSendClient(requestStr, 104);
	char *isIdStr = custom_alloc(IS_ID_LEN);
	memcpy(isIdStr, firstResponse, IS_ID_LEN);
	while(strcmp(isIdStr, IS_ID)!=0){
		int received = udpPollAndRecvClient(50) - 1;
		if(received>=IS_ID_LEN){
			firstResponse = udpGetRecvStrClient();
			memcpy(isIdStr, firstResponse, IS_ID_LEN);
		}
		else{
			vTaskDelay(MSEC_TO_TICK(50));
		}
	}

	char *challangeStr = custom_alloc(CHALLANGE_LEN);
	char *authIsStr = custom_alloc(AUTH_IS_LEN);

	memcpy(isIdStr, firstResponse, IS_ID_LEN);
	int offset = IS_ID_LEN;
	memcpy(challangeStr, firstResponse + offset, CHALLANGE_LEN);
	offset += CHALLANGE_LEN;
	memcpy(authIsStr, firstResponse + offset, AUTH_IS_LEN);

	char attest_full_message[41];
	snprintf(attest_full_message, sizeof(attest_full_message), "%s%s", isIdStr, challangeStr);
	uint8_t attest_message_bytes[20] = {0};
	convert_hex(attest_message_bytes, 20, attest_full_message);

	//check auth_is
	uint8_t auth_is_bytes[32] = {0};
	convert_hex(auth_is_bytes, 32, authIsStr);

	uint8_t resp[32] = {0};
	uint8_t checkAuthIsResult = check_auth_is((uint8_t*) resp, (uint8_t*) attest_message_bytes, (uint8_t*) auth_is_bytes, 20);
	char *replyStr = custom_alloc(TICKET_LEN+1);
	convert_bytes(replyStr, 32, resp);
	if(checkAuthIsResult != 0){
		char *returnMessage = custom_alloc(18);
		snprintf(returnMessage, 18, "%s", "Invalid Request!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}
	uint8_t session_key[32] = {0};
	uint8_t challange_bytes[16] = {0};
	convert_hex(challange_bytes, 16, challangeStr);
	calculate_session_key((uint8_t*) session_key, (uint8_t*) challange_bytes, 16);
	run_attestation((uint8_t*) resp, (uint8_t*) session_key, (uint8_t*) saddr, MEM_SIZE);
	convert_bytes(replyStr, 32, resp);

	uint8_t attestation_response[36] = {0};
	memcpy((uint8_t*) attestation_response, (uint8_t*) iot_id_bytes, 4);
	offset = 4;
	memcpy((uint8_t*) attestation_response+offset, (uint8_t*) resp, 32);
	char *attestation_response_str = custom_alloc(73);
	convert_bytes(attestation_response_str, 36, attestation_response);

	char *response = custom_alloc(136);
	zero_copy_free(firstResponse);
	response = udpSendClientPort(attestation_response_str, 72, 12346);
	char *resetCounterStr = custom_alloc(RESET_COUNTER_LEN);
	char *localCounterStr = custom_alloc(COUNTER_LEN);

	memcpy(isIdStr, response, IS_ID_LEN);
	offset = IS_ID_LEN;
	memcpy(resetCounterStr, response + offset, RESET_COUNTER_LEN);
	offset += RESET_COUNTER_LEN;
	memcpy(localCounterStr, response + offset, COUNTER_LEN);
	offset += TIME_STAMP_LEN;
	memcpy(authIsStr, response + offset, AUTH_IS_LEN);

// check reset counter value
	uint32_t resetCounterVal = atoi(resetCounterStr);
	uint8_t resetCounterResult = check_reset_counter(resetCounterVal);
	if(resetCounterResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 15, "%s", "Stale Request!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}

	char full_message[73];
	snprintf(full_message, sizeof(full_message), "%s%s%s", isIdStr, resetCounterStr, localCounterStr);
	uint8_t message_bytes[36] = {0};
	convert_hex(message_bytes, 36, full_message);

	//check auth_is
	convert_hex(auth_is_bytes, 32, authIsStr);

	checkAuthIsResult = check_auth_is((uint8_t*) resp, (uint8_t*) message_bytes, (uint8_t*) auth_is_bytes, 36);

	convert_bytes(replyStr, 32, resp);
	if(checkAuthIsResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 18, "%s", "Invalid Response!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}
	uint32_t local_counter = atoi(localCounterStr);
	set_local_counter(local_counter);

	zero_copy_free(response);
	free(replyStr);
	return 0;
}

int updateTimeStampValue(){
	uint8_t sync_val_update_request[52] = {0};
	uint8_t iot_id_bytes[4] = {0};
	convert_hex(iot_id_bytes, 4, IoT_ID);
	memcpy((uint8_t*) sync_val_update_request, (uint8_t*) iot_id_bytes, 4);
	prepare_update_request((uint8_t*) sync_val_update_request);
	char *requestStr = custom_alloc(105);
	convert_bytes(requestStr, 52, sync_val_update_request);
	char *response = custom_alloc(136);
	response = udpSendClient(requestStr, 104);
	char *isIdStr = custom_alloc(IS_ID_LEN);
	char *resetCounterStr = custom_alloc(COUNTER_LEN);
	char *timestampStr = custom_alloc(TIME_STAMP_LEN);
	char *authIsStr = custom_alloc(AUTH_IS_LEN);

	memcpy(isIdStr, response, IS_ID_LEN);
	int offset = IS_ID_LEN;
	memcpy(resetCounterStr, response + offset, RESET_COUNTER_LEN);
	offset += RESET_COUNTER_LEN;
	memcpy(timestampStr, response + offset, TIME_STAMP_LEN);
	offset += TIME_STAMP_LEN;
	memcpy(authIsStr, response + offset, AUTH_IS_LEN);

// check reset counter value
	uint32_t resetCounterVal = atoi(resetCounterStr);
	uint8_t resetCounterResult = check_reset_counter(resetCounterVal);
	if(resetCounterResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 15, "%s", "Stale Request!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}

	char full_message[73];
	snprintf(full_message, sizeof(full_message), "%s%s%s", isIdStr, resetCounterStr, timestampStr);
	uint8_t message_bytes[36] = {0};
	convert_hex(message_bytes, 36, full_message);

	//check auth_is
	uint8_t auth_is_bytes[32] = {0};
	convert_hex(auth_is_bytes, 32, authIsStr);

	uint8_t resp[32] = {0};
	uint8_t checkAuthIsResult = check_auth_is((uint8_t*) resp, (uint8_t*) message_bytes, (uint8_t*) auth_is_bytes, 36);

	char *replyStr = custom_alloc(TICKET_LEN+1);
	convert_bytes(replyStr, 32, resp);
	if(checkAuthIsResult != 0){
		char *returnMessage = custom_alloc(15);
		snprintf(returnMessage, 18, "%s", "Invalid Response!");
		int length = strlen(returnMessage);
		udpSend(returnMessage, length);
		free(returnMessage);
		return;
	}

	uint32_t start_timestamp = atoi(timestampStr);
	set_start_time_stamp(start_timestamp);

	zero_copy_free(response);
	free(replyStr);
	return 0;
}

/* Initialize WiFi before the main loop. */
void initializeWifi()
{
    int32_t result = 0;
    (void)result;

    /* Initialize WIFI shield */
    result = WIFISHIELD_Init();
    assert(A_OK == result);
    /* Initialize the WIFI driver (thus starting the driver task) */
    result = wlan_driver_start();
    assert(A_OK == result);

    print_version();

    UBaseType_t numTasks = uxTaskGetNumberOfTasks();
    PRINTF("number of FreeRTOS tasks = %d\r\n", numTasks);
    DbgConsole_Flush();
    PRINTF("Entering main loop\r\n");
    apConnect(&g_ssid, &g_passphrase, g_auth, g_cipher);
    getDhcp();
    udpBind(PORT_NUM);
}

void task_main(void *param)
{
    /* This task calls secure side functions. So allocate a
     * secure context for it. */
    portALLOCATE_SECURE_CONTEXT(configMINIMAL_SECURE_STACK_SIZE);
    initializeWifi();
    DWT->CTRL |= (1 << DWT_CTRL_CYCCNTENA_Pos);
    DWT->CYCCNT = 0;
    uint8_t resp[32] = {0};
    get_memory_digest((uint8_t*)saddr, MEM_SIZE, (uint8_t*) resp);
	char *replyStr = custom_alloc(65);
	convert_bytes(replyStr, 32, resp);
	PRINTF("Fixed memory hash is:\r\n %s\r\n", replyStr);
	free(replyStr);
    PRINTF("Select mode:\r\n Press n for normal mode, p for power constrained mode\r\n");
    char mode = GETCHAR();
    if(mode=='n'){
        while(timestamp_update_flag==0){
        	int timestampUpdateResult = updateTimeStampValue();
        	if(timestampUpdateResult==0){
        		timestamp_update_flag = 1;
        	}
        	vTaskDelay(MSEC_TO_TICK(50));
        }
        start_timer();
    }
    else{
    	while(counter_update_flag==0){
			int counterUpdateResult = updateCounterValue();
			if(counterUpdateResult==0){
				counter_update_flag = 1;
			}
			vTaskDelay(MSEC_TO_TICK(50));
		}
    }

    while (1)
    {
    	/* We always receive the string with '\0'; hence the '-1'. */
        int received = udpPollAndRecv(50) - 1;
        if (received >= 1)
        {
        	char *recvStr = udpGetRecvStr();
        	if(mode=='n'){
        		processMessageTimer(recvStr);
        	}
        	else{
        		processMessageCounter(recvStr);
        	}
        }
        else
        {
            vTaskDelay(MSEC_TO_TICK(50));
        }
    }
}


/* FreeRTOS functions  */
void SystemInit(void)
{
#if ((__FPU_PRESENT == 1) && (__FPU_USED == 1))
    SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2)); /* set CP10, CP11 Full Access */
#endif                                                 /* ((__FPU_PRESENT == 1) && (__FPU_USED == 1)) */

    SCB->CPACR |= ((3UL << 0 * 2) | (3UL << 1 * 2)); /* set CP0, CP1 Full Access (enable PowerQuad) */

    SCB->NSACR |= ((3UL << 0) | (3UL << 10)); /* enable CP0, CP1, CP10, CP11 Non-secure Access */
}


static void prvCreateTasks(void)
{
    /* Create the WiFi task. */
	BaseType_t result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
	assert(pdPASS == result);
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory(StaticTask_t **ppxIdleTaskTCBBuffer,
                                   StackType_t **ppxIdleTaskStackBuffer,
                                   uint32_t *pulIdleTaskStackSize)
{
    /* If the buffers to be provided to the Idle task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[configMINIMAL_STACK_SIZE + 100];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE + 100;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION and configUSE_TIMERS are both set to 1, so the
 * application must provide an implementation of vApplicationGetTimerTaskMemory()
 * to provide the memory that is used by the Timer service task. */
void vApplicationGetTimerTaskMemory(StaticTask_t **ppxTimerTaskTCBBuffer,
                                    StackType_t **ppxTimerTaskStackBuffer,
                                    uint32_t *pulTimerTaskStackSize)
{
    /* If the buffers to be provided to the Timer task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[configTIMER_TASK_STACK_DEPTH];

    /* Pass out a pointer to the StaticTask_t structure in which the Timer
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configTIMER_TASK_STACK_DEPTH is specified in words, not bytes. */
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}

/* Non-secure main(). */
/*!
 * @brief Main function
 */
int main(void)
{
    /* set BOD VBAT level to 1.65V */
    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);
    /* Get the updated SystemCoreClock from the secure side */
    SystemCoreClock = getSystemCoreClock();

	/* Need to initialize the debug console as well on the NS side */
	BOARD_InitDebugConsole();

    /* Create tasks. */
    prvCreateTasks();

    /* Start the scheduler. */
    vTaskStartScheduler();

    /* Should not reach here as the scheduler is
     * already started. */
    for (;;)
    {
    }
}
