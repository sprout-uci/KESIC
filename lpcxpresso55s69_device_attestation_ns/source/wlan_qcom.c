/*
 * Copyright (c) 2013 - 2014, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// SDK Included Files
#include <stdio.h>
#include <stdlib.h>
#include "fsl_debug_console.h"
#include "qcom_api.h"
#include "wlan_qcom.h"

// devId used for first argument of all the qcom API functions
static int devId = 0;

// Values used by qcom_ipconfig()
struct network_ipv4_s
{
    uint32_t addr;
    uint32_t mask;
    uint32_t gateway;
} ipv4;

static int _traceQcomApi = 0;

// ============================================================================
// Defines
// ============================================================================

// Convert IP address in uint32_t to comma separated bytes
#define UINT32_IPADDR_TO_CSV_BYTES(a) \
    ((uint8_t)((a) >> 24) & 0xFF), (uint8_t)(((a) >> 16) & 0xFF), (uint8_t)(((a) >> 8) & 0xFF), (uint8_t)((a)&0xFF)
// Convert comma separated bytes to a uint32_t IP address
#define CSV_BYTES_TO_UINT32_IPADDR(a0, a1, a2, a3) \
    (((uint32_t)(a0)&0xFF) << 24) | (((uint32_t)(a1)&0xFF) << 16) | (((uint32_t)(a2)&0xFF) << 8) | ((uint32_t)(a3)&0xFF)
#define CONSTSTR_LEN(variable) (sizeof(variable) - 1)

// ============================================================================
// Utility Functions
// ============================================================================

static void printError(uint32_t value, const char *funcName)
{
    PRINTF("ERROR: %s() returned %d\r\n", funcName, value);
}

static int isQcomError(A_STATUS status, const char *funcName)
{
    if (status != A_OK)
    {
        printError(status, funcName);
    }
    else if (_traceQcomApi)
    {
        PRINTF("%s() OK\r\n", funcName);
    }
    return (status != A_OK);
}

static int isValueFailed(int32_t value, int32_t failValue, const char *funcName)
{
    if (value == failValue)
    {
        printError(value, funcName);
    }
    else if (_traceQcomApi)
    {
        PRINTF("%s() OK\r\n", funcName);
    }
    return (value == failValue);
}

/** Enable printing/tracing of QCOM functions calls
 *  @param enable   0 = disable
 *                  1 = enable
 *                 -1 = toggle
 *  @return         previous value
 */
int traceQcomApi(int enable)
{
    int oldValue = _traceQcomApi;
    if (enable == -1)
        _traceQcomApi = !_traceQcomApi;
    else
        _traceQcomApi = enable;
    return oldValue;
}

// ============================================================================
// IP config and DHCP
// ============================================================================

// Although indicated in the QCA 80-Y9106-1 doc, this enum is unfortunately not defined
enum ipconfigActions
{
    IP_CONFIG_QUERY = 0,
    IP_CONFIG_SET   = 1,
    IP_CONFIG_DHCP  = 2,
};

void getDhcp(void)
{
    A_STATUS status;

    PRINTF("Getting DHCP address...\r\n");

    for (int32_t i = 20; i > 0; i--)
    {
        status = qcom_ipconfig(devId, QCOM_IPCONFIG_DHCP, &ipv4.addr, &ipv4.mask, &ipv4.gateway);
        A_MDELAY(50);
        status = qcom_ipconfig(devId, QCOM_IPCONFIG_QUERY, &ipv4.addr, &ipv4.mask, &ipv4.gateway);
        if (ipv4.addr != 0)
        {
            break;
        }
    }

    if (isQcomError(status, "qcom_ipconfig"))
        return;

    // Print the DNS servers we got from the DHCP server
    uint32_t dnsServers[3];
    uint32_t num;
    status = qcom_dns_server_address_get(dnsServers, &num);
    if (isQcomError(status, "qcom_dns_server_address_get"))
    {
        PRINTF("WARNING: No DNS servers returned by DHCP\r\n");
        PRINTF("         You will NOT be able to resolve domain names\r\n");
        return;
    }

    for (int i = 0; i < num; i++)
    {
        PRINTF("DNS %d: %d.%d.%d.%d\r\n", i, UINT32_IPADDR_TO_CSV_BYTES(dnsServers[i]));
    }

    printIpConfig();
}

void printIpConfig(void)
{
    A_STATUS status = qcom_ipconfig(devId, QCOM_IPCONFIG_QUERY, &ipv4.addr, &ipv4.mask, &ipv4.gateway);
    isQcomError(status, "qcom_ipconfig");

    PRINTF("addr: %d.%d.%d.%d mask: %d.%d.%d.%d gw: %d.%d.%d.%d\r\n", UINT32_IPADDR_TO_CSV_BYTES(ipv4.addr),
           UINT32_IPADDR_TO_CSV_BYTES(ipv4.mask), UINT32_IPADDR_TO_CSV_BYTES(ipv4.gateway));
}

// ============================================================================
// Scanning and Access Point Connect/Disconnect
// ============================================================================

char _isConnected = 0;

static void onConnect(uint8_t event, uint8_t devId, char *bssid, uint8_t bssConn)
{
    PRINTF("EVENT: ");

    switch (event)
    {
        case 1:
            if (devId == 0)
            {
                PRINTF("%s connected\r\n", bssConn ? "AP" : "CLIENT");
            }
            else
            {
                PRINTF("Connected\r\n");
            }
            // NOTE that station is not fully connected until PEER_FIRST_NODE_JOIN_EVENT
            break;
        case INVALID_PROFILE:
            // this event is used to indicate RSNA failure
            _isConnected = 0;
            PRINTF("4 way handshake failure for device=%d n", devId);
            break;
        case PEER_FIRST_NODE_JOIN_EVENT:
            // this event is used to RSNA success
            _isConnected = 1;
            PRINTF("4 way handshake success for device=%d\r\n", devId);
            break;
        case 0:
            _isConnected = 0;
            if (devId == 0)
            {
                PRINTF("%s disconnect\r\n", bssConn ? "AP" : "CLIENT");
            }
            break;

        default:
            PRINTF("code %d\r\n");
    }
}

int isConnected(void)
{
    return _isConnected;
}

static void apConnectParamsPrint(void)
{
    A_STATUS status;

    PRINTF("Reading connection params\r\n");

    // Get current operational mode
    QCOM_WLAN_DEV_MODE opMode = QCOM_WLAN_DEV_MODE_INVALID;
    status                    = qcom_op_get_mode(devId, &opMode);
    isQcomError(status, "qcom_op_get_mode");
    PRINTF("  opMode=%d (%s)\r\n", opMode, (opMode == 0 ? "Station" : "AP"));

    char *phyMode = NULL;
    status        = qcom_get_phy_mode(devId, &phyMode);
    isQcomError(status, "qcom_get_phy_mode");
    if (NULL != phyMode)
    {
        PRINTF("  phyMode=%s\r\n", phyMode);
    }

    // NOTE: Listed in QCA 80-Y9106-1 although not implemented by driver
    // uint32_t authMode
    // status = qcom_sec_get_auth_mode(devId, &authMode);
    // checkForError(status, "qcom_sec_get_auth_mode");

    QCOM_SSID ssidRead = {0};
    status             = qcom_get_ssid(devId, &ssidRead);
    isQcomError(status, "qcom_get_ssid");
    PRINTF("  ssid=%s\r\n", ssidRead.ssid);
}

static char *getSecurityStr(uint8_t auth, uint8_t cipher)
{
    static char s[100];
    char *p = s;
    s[0]    = 0;

    if (auth & SECURITY_AUTH_1X)
        p += sprintf(p, "802.1X ");
    if (auth & SECURITY_AUTH_PSK)
        p += sprintf(p, "PSK ");

    p += sprintf(p, "/ ");

    if (cipher & ATH_CIPHER_TYPE_WEP)
        p += sprintf(p, "WEP ");
    if (cipher & ATH_CIPHER_TYPE_TKIP)
        p += sprintf(p, "TKIP ");
    if (cipher & ATH_CIPHER_TYPE_CCMP)
        p += sprintf(p, "CCMP ");

    return s;
}

void apScan(void)
{
    A_STATUS status;

    // NOTE: If scan is initiated when SSID is set to a value then only that SSID is scanned
    status = qcom_set_scan(devId, NULL);
    isQcomError(status, "qcom_set_scan");

    // NOTE: calling qcom_get_scan() before qcom_set_scan() is the same as suspending for 5s,
    // i.e. nothing happens for 5s where after 0 is returned
    // NOTE: A maximum of 12 results are returned
    QCOM_BSS_SCAN_INFO *scanResult;
    int16_t scanNumResults = 0;
    status                 = qcom_get_scan(devId, &scanResult, &scanNumResults);
    isQcomError(status, "qcom_get_scan");
    // PRINTF("qcom_get_scan numResults=%d\r\n", scanNumResults);

    PRINTF(" i Ch RSSI  MAC                SSID\r\n");
    for (int i = 0; i < scanNumResults; i++)
    {
        QCOM_BSS_SCAN_INFO *scr = &scanResult[i];
        int ssidLen             = scr->ssid_len;
        scr->ssid[ssidLen]      = 0;

        PRINTF("%2d %2d %4d  %02x:%02x:%02x:%02x:%02x:%02x  %s\r\n", i, scr->channel, scr->rssi, scr->bssid[0],
               scr->bssid[1], scr->bssid[2], scr->bssid[3], scr->bssid[4], scr->bssid[5], scr->ssid);

        if (scr->security_enabled)
        {
            if (scr->rsn_cipher == 0 && scr->wpa_cipher == 0)
            {
                PRINTF("            WEP\r\n");
            }
            else
            {
                char *secStr;
                secStr = getSecurityStr(scr->rsn_auth, scr->rsn_cipher);
                PRINTF("            RSN: %s\r\n", secStr);
                secStr = getSecurityStr(scr->wpa_auth, scr->wpa_cipher);
                PRINTF("            WPA: %s\r\n", secStr);
            }
        }
        else
        {
            PRINTF("            open AP\r\n");
        }
    }

    PRINTF("--------------------\r\n");
}

void apConnect(QCOM_SSID *ssid, QCOM_PASSPHRASE *passphrase, WLAN_AUTH_MODE auth, WLAN_CRYPT_TYPE cipher)
{
    A_STATUS status;

    // Set station mode to station (0) or AP (1)
    status = qcom_op_set_mode(devId, QCOM_WLAN_DEV_MODE_STATION);
    isQcomError(status, "qcom_op_set_mode");

    // Optionally set the PHY mode
    // status = qcom_set_phy_mode(devId, QCOM_11G_MODE);
    // checkForError(status, "qcom_set_phy_mode");

    // NOTE: qcom API requires to first set a valid SSID (before auth, cipher and passphrase)
    status = qcom_set_ssid(devId, ssid);
    isQcomError(status, "qcom_set_ssid");

    status = qcom_sec_set_encrypt_mode(devId, cipher);
    isQcomError(status, "qcom_sec_set_encrypt_mode");

    // Note that only 4 of all modes listed in QCA 80-Y9106-1 are supported!
    // The modes are: WLAN_AUTH_NONE, WLAN_AUTH_WPA_PSK, WLAN_AUTH_WPA2_PSK, WLAN_AUTH_WEP
    status = qcom_sec_set_auth_mode(devId, auth);
    isQcomError(status, "qcom_sec_set_auth_mode");

    // NOTE: The driver insists that the SSID is configured *before* the passphrase
    status = qcom_sec_set_passphrase(devId, passphrase);
    isQcomError(status, "qcom_sec_set_passphrase");

    // The connect callback is actually used for four different callbacks:
    //     onConnect(1 (TRUE), uint8_t devId, uint8_t *ssid, uint8_t bssMac[6]);
    //     onDisconnect(status, uint8_t devId, uint8_t *ssid, uint8_t bssMac[6]);
    //         where status = 0x10 (INVALID_PROFILE) on ?
    //                      =    0 on normal disconnect
    //     onRSNASuccessEvent(uint8_t code, uint8_t devId, NULL, 0)
    //     onBitRateEvent_tx(wmi_rateTable[rateIndex][0], devId, NULL, 0);
    // It is not possible to discern the onBitRateEvent_tx event from the others
    status = qcom_set_connect_callback(devId, (void *)onConnect);
    isQcomError(status, "qcom_set_connect_callback");

    apConnectParamsPrint();

    status = qcom_commit(devId);
    isQcomError(status, "qcom_commit");
}

void apDisconnect(void)
{
    A_STATUS status = qcom_disconnect(devId);
    isQcomError(status, "qcom_disconnect");
}



// ============================================================================
// UDP example
// ============================================================================
#define SERVER_ADDRESS_FIRST 192
#define SERVER_ADDRESS_SECOND 168
#define SERVER_ADDRESS_THIRD 158
#define SERVER_ADDRESS_FOURTH 13
#define SERVER_ADDRESS_PORT 12345
#define SERVER_TIMEOUT 90
static int32_t udpSock   = 0;
static int32_t udpSockClient   = 0;
static char *udpRecvBuf  = NULL;
static char *udpRecvBufClient  = NULL;
static int udpRecvBufLen = 0;
static int udpRecvBufLenClient = 0;

// IPv4 address of remote peer
static SOCKADDR_T remAddr;
static socklen_t remAddrLen;
static SOCKADDR_T serverAddr;
static socklen_t serverAddrLen;

static void udpHelp(uint16_t port)
{
    PRINTF("\r\n");
    PRINTF("Test UDP echo server from your Unix workstation with the netcat command:\r\n");
    PRINTF("  echo 'hello' | netcat -u -q1 %d.%d.%d.%d %d\r\n", UINT32_IPADDR_TO_CSV_BYTES(ipv4.addr), port);
}
void udpBind(uint16_t port)
{
    A_STATUS status;
    SOCKADDR_T localAddr;

    if (udpSock)
    {
        PRINTF("UDP echo server socket already created\r\n");
        udpHelp(port);
        return;
    }

    udpSock = qcom_socket(ATH_AF_INET, SOCK_DGRAM_TYPE, 0);
    if (isValueFailed(udpSock, -1, "qcom_socket"))
        return;

    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_port        = port;
    localAddr.sin_family      = ATH_AF_INET;
    localAddr.sin_addr.s_addr = CSV_BYTES_TO_UINT32_IPADDR(0, 0, 0, 0);

    status = 0 == qcom_bind(udpSock, (struct sockaddr *)(&localAddr), sizeof(localAddr)) ? A_OK : A_ERROR;
    if (isQcomError(status, "qcom_bind"))
        return;

//    PRINTF("UDP echo server listening on port %d\r\n", port);
    udpHelp(port);
}

/** Poll for UDP packet for [timeout] ms
 *  Return  -1 on timeout
 *          -9 if UDP socket hasn't been opened
 *          Otherwise, number of bytes received
 */
int udpPollAndRecv(int timeout)
{
    // Return immediately if UDP listen socket hasn't been created yet
    if (udpSock == 0)
        return -9;

    // NOTE: There is no qcom_select() function, only t_select() that polls only one socket
    // NOTE: t_select() does NOT take a devId like all the other functions
    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    int32_t status              = t_select(enetCtx, udpSock, timeout);
    if (status == -1)
        return A_ERROR;

    // Free the ZERO_COPY receive buffer (from previous call of this function)
    if (udpRecvBuf != NULL)
    {
        // PRINTF("Freeing old buffer\r\n");
        zero_copy_free(udpRecvBuf);
        udpRecvBuf    = NULL;
        udpRecvBufLen = 0;
    }

    // NOTE: when QCA400x library has been compiled with ZERO_COPY, the recvBuf
    // is allocated by the qcom_recv() function and the user must free it afterwards!
    // NOTE: qcom_recvfrom() buffer argument is of type char although it should be void
    int received = qcom_recvfrom(udpSock, &udpRecvBuf, 500, 0, (struct sockaddr *)&remAddr, &remAddrLen);
    if (received <= 0)
    {
        PRINTF("qcom_recvfrom() ERROR: %d\r\n", received);
    }
//    PRINTF("UDP received %d bytes from %d.%d.%d.%d:%d\r\n", received,
//           UINT32_IPADDR_TO_CSV_BYTES(remAddr.sin_addr.s_addr), remAddr.sin_port);

    udpRecvBufLen = received;
    return received;
}

char* udpGetRecvStr(void)
{
    return udpRecvBuf;
}

int udpSend(char *sendStr, int sendStrLen)
{
    int sent = qcom_sendto(udpSock, sendStr, sendStrLen, 0, (struct sockaddr *)&remAddr, remAddrLen);
//    PRINTF("UDP sent %d bytes\r\n", sent);

    return sent;
}

int udpPollAndRecvClient(int timeout)
{
    // Return immediately if UDP listen socket hasn't been created yet
    if (udpSockClient == 0)
        return -9;

    // NOTE: There is no qcom_select() function, only t_select() that polls only one socket
    // NOTE: t_select() does NOT take a devId like all the other functions
    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    int32_t status              = t_select(enetCtx, udpSockClient, timeout);
    if (status == -1)
        return A_ERROR;

    // Free the ZERO_COPY receive buffer (from previous call of this function)
    if (udpRecvBufClient != NULL)
    {
        // PRINTF("Freeing old buffer\r\n");
        zero_copy_free(udpRecvBufClient);
        udpRecvBufClient    = NULL;
        udpRecvBufLenClient = 0;
    }

    // NOTE: when QCA400x library has been compiled with ZERO_COPY, the recvBuf
    // is allocated by the qcom_recv() function and the user must free it afterwards!
    // NOTE: qcom_recvfrom() buffer argument is of type char although it should be void
    int received = qcom_recvfrom(udpSockClient, &udpRecvBufClient, 500, 0, (struct sockaddr *)&serverAddr, &serverAddrLen);
    if (received <= 0)
    {
        PRINTF("qcom_recvfrom() ERROR: %d\r\n", received);
    }
    udpRecvBufLenClient = received;
    return received;
}

char* udpGetRecvStrClient(void)
{
    return udpRecvBufClient;
}

char* udpSendClient(char *sendStr, int sendStrLen)
{
    A_STATUS status;
    uint32_t target_address = CSV_BYTES_TO_UINT32_IPADDR(SERVER_ADDRESS_FIRST, SERVER_ADDRESS_SECOND, SERVER_ADDRESS_THIRD, SERVER_ADDRESS_FOURTH);
    serverAddrLen = sizeof(serverAddr);
    memset(&serverAddr, 0, serverAddrLen);
    serverAddr.sin_family = ATH_AF_INET;
    serverAddr.sin_addr.s_addr = target_address;
    serverAddr.sin_port = SERVER_ADDRESS_PORT;
	char* recvStr;
    char *response_data = NULL;
    int i=0;
	do{
		udpSockClient = qcom_socket(ATH_AF_INET, SOCK_DGRAM_TYPE, 0);
		if (isValueFailed(udpSock, -1, "qcom_socket"))
				return;
		status = (A_STATUS)qcom_connect(udpSockClient, (struct sockaddr *)&serverAddr, serverAddrLen);
		if (isQcomError(status, "qcom_connect"))
			return;
		int sent = qcom_sendto(udpSockClient, sendStr, sendStrLen, 0, (struct sockaddr *)&serverAddr, serverAddrLen);
		int received = udpPollAndRecvClient(50) - 1;
		if (received >= 1)
		{
			recvStr = udpGetRecvStrClient();
			break;
		}
		i++;
		vTaskDelay(MSEC_TO_TICK(10));
	}while(i<3);
	return recvStr;
}

char* udpSendClientPort(char *sendStr, int sendStrLen, int port)
{
    A_STATUS status;
    uint32_t target_address = CSV_BYTES_TO_UINT32_IPADDR(SERVER_ADDRESS_FIRST, SERVER_ADDRESS_SECOND, SERVER_ADDRESS_THIRD, SERVER_ADDRESS_FOURTH);
    serverAddrLen = sizeof(serverAddr);
    memset(&serverAddr, 0, serverAddrLen);
    serverAddr.sin_family = ATH_AF_INET;
    serverAddr.sin_addr.s_addr = target_address;
    serverAddr.sin_port = port;
	char* recvStr;
    char *response_data = NULL;
    int i=0;
	do{
		udpSockClient = qcom_socket(ATH_AF_INET, SOCK_DGRAM_TYPE, 0);
		if (isValueFailed(udpSock, -1, "qcom_socket"))
				return;
		status = (A_STATUS)qcom_connect(udpSockClient, (struct sockaddr *)&serverAddr, serverAddrLen);
		if (isQcomError(status, "qcom_connect"))
			return;
		int sent = qcom_sendto(udpSockClient, sendStr, sendStrLen, 0, (struct sockaddr *)&serverAddr, serverAddrLen);
		int received = udpPollAndRecvClient(50) - 1;
		if (received >= 1)
		{
			recvStr = udpGetRecvStrClient();
			break;
		}
		i++;
		vTaskDelay(MSEC_TO_TICK(10));
	}while(i<3);
	return recvStr;
}
