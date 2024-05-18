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
/* Trustzone config. */
#include "tzm_config.h"

/* FreeRTOS includes. */
#include "secure_port_macros.h"

#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_power.h"
#include "fsl_debug_console.h"


/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define BOARD_LED_PORT BOARD_LED_GREEN_GPIO_PORT
#define BOARD_LED_PIN BOARD_LED_GREEN_GPIO_PIN

/**
 * @brief Start address of non-secure application.
 */
#define DEMO_CODE_START_NS 0x00030000
#define mainNONSECURE_APP_START_ADDRESS DEMO_CODE_START_NS

/**
 * @brief LED port and pins.
 */
#define LED_PORT      BOARD_LED_BLUE_GPIO_PORT
#define GREEN_LED_PIN BOARD_LED_GREEN_GPIO_PIN
#define BLUE_LED_PIN  BOARD_LED_BLUE_GPIO_PIN

/**
 * @brief typedef for non-secure Reset Handler.
 */
#if defined(__IAR_SYSTEMS_ICC__)
typedef __cmse_nonsecure_call void (*NonSecureResetHandler_t)(void);
#else
typedef void (*NonSecureResetHandler_t)(void) __attribute__((cmse_nonsecure_call));
#endif
/*-----------------------------------------------------------*/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/**
 * @brief Application-specific implementation of the SystemInitHook().
 */
void SystemInitHook(void);

/**
 * @brief Boots into the non-secure code.
 *
 * @param[in] ulNonSecureStartAddress Start address of the non-secure application.
 */
void BootNonSecure(uint32_t ulNonSecureStartAddress);
/*-----------------------------------------------------------*/

/*******************************************************************************
 * Code
 ******************************************************************************/
void SystemInitHook(void)
{
    /* The TrustZone should be configured as early as possible after RESET.
     * Therefore it is called from SystemInit() during startup. The
     * SystemInitHook() weak function overloading is used for this purpose.
     */
    BOARD_InitTrustZone();
}
/*-----------------------------------------------------------*/

void BootNonSecure(uint32_t ulNonSecureStartAddress)
{
    NonSecureResetHandler_t pxNonSecureResetHandler;

    /* Main Stack Pointer value for the non-secure side is the first entry in
     * the non-secure vector table. Read the first entry and assign the same to
     * the non-secure main stack pointer(MSP_NS). */
    secureportSET_MSP_NS(*((uint32_t *)(ulNonSecureStartAddress)));

    /* Reset handler for the non-secure side is the second entry in the
     * non-secure vector table. */
    pxNonSecureResetHandler = (NonSecureResetHandler_t)(*((uint32_t *)((ulNonSecureStartAddress) + 4U)));

    /* Start non-secure state software application by jumping to the non-secure
     * reset handler. */
    pxNonSecureResetHandler();
}
/*-----------------------------------------------------------*/

/* Secure main(). */
/*!
 * @brief Main function
 */
int main(void)
{
    /* Init board hardware. */
	/* set BOD VBAT level to 1.65V */
	POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);
	gpio_pin_config_t xLedConfig = {.pinDirection = kGPIO_DigitalOutput, .outputLogic = 1};

	/* Initialize GPIO for LEDs. */
	GPIO_PortInit(GPIO, LED_PORT);
	GPIO_PinInit(GPIO, LED_PORT, GREEN_LED_PIN, &(xLedConfig));
	GPIO_PinInit(GPIO, LED_PORT, BLUE_LED_PIN, &(xLedConfig));

	/* Set non-secure vector table */
	SCB_NS->VTOR = mainNONSECURE_APP_START_ADDRESS;

	/* attach main clock divide to FLEXCOMM0 (debug console) */
	CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

//    PRINTF("STEP 1: Hello from secure world!\r\n");

	/* Boot the non-secure code. */
	BootNonSecure(mainNONSECURE_APP_START_ADDRESS);

	/* Non-secure software does not return, this code is not executed. */
	for (;;)
	{
	}
}
