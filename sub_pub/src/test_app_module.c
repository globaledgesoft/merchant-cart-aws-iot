/************************************************************************
 *   Copyright (c) xxxx - xxxx GlobalEdge Software Ltd.
 *    ************************************************************************
 *    NOTICE:
 *    This document contains information that is confidential and proprietary
 *    to GlobalEdge Software Ltd.. No part of this document may be
 *    reproduced in any form whatsoever without written prior approval by
 *    GlobalEdge Software Ltd.
 *
 *    GlobalEdge Software Ltd. reserve the right to revise this
 *    publication and make changes without obligation to notify any person of
 *    such revisions or changes.
 *    ***********************************************************************/

/**
 *   @project AWS-BG96-PORTING
 *   @file test_app_module.c
 *   @brief This file contains application sample for AWS MQTT
 *   @Author 
 **/

/*================================== REVISION HISTORY===========================*/

#include "txm_module.h"                                                          
#include "qapi_diag.h"                                                           
#include "qapi_timer.h"                                                          
#include "qapi_uart.h"                                                           
#include "quectel_utils.h"                                                       
#include "quectel_uart_apis.h"                                                   
#include "qapi_fs_types.h"                                                       
#include "qapi_fs.h"                                                             
#include "qapi_mqtt.h"                                                           
#include "string.h"                                                              
#include "qapi_status.h"                                                         
#include "limits.h"
#include "txm_module.h"                                                          
#include "qapi_dss.h"                                                            
#include "qapi_netservices.h"                                                    
#include "qapi_net_status.h"                                                     
#include "qapi_socket.h"                                                         
#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "queue_config.h"
                                                                                 
#include <stdlib.h>                                                              
#include <stdio.h>                                                               
#include <stdint.h>                                                              
#include <errno.h>                                                               
#include <string.h>                                                              
extern TX_QUEUE tx_queue_handle;                                                                               

#define HOST_ADDRESS_SIZE 255
#define PATH_MAX 255


//#define QL_DEF_APN          "airtelgprs.com"                                              
#define DSS_ADDR_INFO_SIZE  5                                                    
#define DSS_ADDR_SIZE       16                                                   
                                                                                 
#define GET_ADDR_INFO_MIN(a, b) ((a) > (b) ? (b) : (a))                          
                                                                                 
                                                                                 
#define THREAD_STACK_SIZE    (1024 * 16)                                         
#define THREAD_PRIORITY      (180)                                               
#define BYTE_POOL_SIZE       (1024 * 16)                                         
                                                                                 
#define CMD_BUF_SIZE  100                                                        
                                                                                 
#define DEFAULT_PUB_TIME 5                                                       
            
/* TCPClient dss thread handle */                                                
#ifdef QAPI_TXM_MODULE                                                           
    //static TX_THREAD *dss_thread_handle;                                         
#else                                                                            
    static TX_THREAD _dss_thread_handle;                                         
    static TX_THREAD *ts_thread_handle = &_dss_thread_handle;                    
#endif                                                                           
#define IGAWS_PERIODIC_TIMER_SIGNAL_INTR (5)
#define _htons(x)           ((unsigned short)((((unsigned short)(x) & 0x00ff) << 8) | (((unsigned short)(x) & 0xff00) >> 8)))
#define _ntohs(x)           ((unsigned short)((((unsigned short)(x) & 0x00ff) << 8) | (((unsigned short)(x) & 0xff00) >> 8)))
#define THREAD_STACK_SIZE       (1024 * 16)                                      
#define THREAD_PRIORITY         (180)                                            
#define QUEC_APN_LEN            (QAPI_DSS_CALL_INFO_APN_MAX_LEN + 1)             
#define QUEC_APN_USER_LEN       (QAPI_DSS_CALL_INFO_USERNAME_MAX_LEN + 1)        
#define QUEC_APN_PASS_LEN       (QAPI_DSS_CALL_INFO_PASSWORD_MAX_LEN + 1)        
#define QUEC_DEV_NAME_LEN       (QAPI_DSS_CALL_INFO_DEVICE_NAME_MAX_LEN + 1)     
#define SLEEP_TIME	15

typedef enum DSS_Net_Evt_TYPE                                                    
{                                                                                
    DSS_EVT_INVALID_E = 0x00,   /**< Invalid event. */                           
    DSS_EVT_NET_IS_CONN_E,      /**< Call connected. */                          
    DSS_EVT_NET_NO_NET_E,       /**< Call disconnected. */                       
    DSS_EVT_NET_RECONFIGURED_E, /**< Call reconfigured. */                       
    DSS_EVT_NET_NEWADDR_E,      /**< New address generated. */                   
    DSS_EVT_NET_DELADDR_E,      /**< Delete generated. */                        
    DSS_EVT_NIPD_DL_DATA_E,                                                      
    DSS_EVT_MAX_E                                                                
} DSS_Net_Evt_Type_e;                                                            
                                                                                 
typedef enum DSS_Lib_Status                                                      
{                                                                                
    DSS_LIB_STAT_INVALID_E = -1,                                                 
    DSS_LIB_STAT_FAIL_E,                                                         
    DSS_LIB_STAT_SUCCESS_E,                                                      
    DSS_LIB_STAT_MAX_E                                                           
} DSS_Lib_Status_e;                                                              
                                                                                 
#define LEFT_SHIFT_OP(N)        (1 << (N))                                       
typedef enum DSS_SIG_EVENTS                                                      
{                                                                                
    DSS_SIG_EVT_INV_E       = LEFT_SHIFT_OP(0),                                  
    DSS_SIG_EVT_NO_CONN_E   = LEFT_SHIFT_OP(1),                                  
    DSS_SIG_EVT_CONN_E      = LEFT_SHIFT_OP(2),                                  
    DSS_SIG_EVT_DIS_E       = LEFT_SHIFT_OP(3),                                  
    DSS_SIG_EVT_EXIT_E      = LEFT_SHIFT_OP(4),                                  
    DSS_SIG_EVT_MAX_E       = LEFT_SHIFT_OP(5)                                   
} DSS_Signal_Evt_e;                                                              

#ifdef IP_V6                                                                     
#define ADDRBUF_LEN IP6_ADDRBUF_LEN                                              
#else                                                                            
#define ADDRBUF_LEN 40                                                           
#endif 

//static unsigned char tcp_dss_stack[THREAD_STACK_SIZE];                          
ULONG g_tx_byte_pool_area[BYTE_POOL_SIZE]; 
                                                                                 
TX_EVENT_FLAGS_GROUP tcp_signal_handle;                                          
                                                                                 
qapi_DSS_Hndl_t tcp_dss_handle_dns = NULL;              /* Related to DSS netctrl */ 
                                                                                 
static char apn[QUEC_APN_LEN];                  /* APN */                        
static char apn_username[QUEC_APN_USER_LEN];    /* APN username */               
static char apn_passwd[QUEC_APN_PASS_LEN];      /* APN password */               
                                                                                 
/* @Note: If netctrl library fail to initialize, set this value will be 1,       
 * We should not release library when it is 1.                                   
 */                                                                              
signed char tcp_netctl_lib_status = DSS_LIB_STAT_INVALID_E;                      
unsigned char tcp_datacall_status = DSS_EVT_INVALID_E;                           

//static char quec_dbg_buffer[128];
static char rx_buff[1024];
static char tx_buff[1024];

unsigned int mqtt_init_flag;
/* uart config para*/

qapi_UART_Handle_t mqtt_dbg_uart_handler;
extern QT_UART_CONF_PARA uart1_conf; 


QT_UART_CONF_PARA uart1_conf =
{
	NULL,
	QT_UART_PORT_02,
	tx_buff,
	sizeof(tx_buff),
	rx_buff,
	sizeof(rx_buff),
	115200
};

TX_BYTE_POOL g_tx_byte_pool;
UINT status;
/**
 * @brief Default cert location
 */
static char certDirectory[PATH_MAX + 1] = "/datatx";


/**
 * @brief Default MQTT HOST URL is pulled from the aws_iot_config.h
 */
static char HostAddress[HOST_ADDRESS_SIZE] = AWS_IOT_MQTT_HOST;

/**
 * @brief Default MQTT port is pulled from the aws_iot_config.h
 */
static uint32_t port = AWS_IOT_MQTT_PORT;


/**************************************************************************
*                                 DEFINE
***************************************************************************/
#define QT_SUB1_THREAD_PRIORITY   	180
#define QT_SUB1_THREAD_STACK_SIZE 	(1024 * 16)

/**************************************************************************
*                                 GLOBAL
***************************************************************************/
/* uart rx tx buffer */
static char rx_buff[1024];
static char tx_buff[1024];

static void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData) {
	qt_uart_dbg(uart1_conf.hdlr,"Subscribe callback");
}

static void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) {
	unsigned int rc = FAILURE;

	qt_uart_dbg(uart1_conf.hdlr,"MQTT Disconnect");
	if(NULL == pClient) {
		return;
	}


	if(aws_iot_is_autoreconnect_enabled(pClient)) {
		IOT_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
	    qt_uart_dbg(uart1_conf.hdlr,"Auto Reconnect is enabled, Reconnecting attempt will start now");
	} 
	else {
	    qt_uart_dbg(uart1_conf.hdlr,"Auto Reconnect not enabled. Starting manual reconnect...");
		rc = aws_iot_mqtt_attempt_reconnect(pClient);

		if(NETWORK_RECONNECTED == rc) {
	        qt_uart_dbg(uart1_conf.hdlr,"Manual Reconnect Successful");
		} else {
	        qt_uart_dbg(uart1_conf.hdlr,"Manual Reconnect Failed - %d", rc);
		}
	}
}

static int tcp_set_data_param(void)                                              
{                                                                                
    qapi_DSS_Call_Param_Value_t param_info;                                      
                                                                                 
    /* Initial Data Call Parameter */                                            
    memset(apn, 0, sizeof(apn));                                                 
    memset(apn_username, 0, sizeof(apn_username));
    memset(apn_passwd, 0, sizeof(apn_passwd));
    /*strlcpy(apn, QL_DEF_APN, QAPI_DSS_CALL_INFO_APN_MAX_LEN);                    
    strlcpy(apn_username, QL_DEF_APN, QAPI_DSS_CALL_INFO_USERNAME_MAX_LEN);                    
    strlcpy(apn_passwd, QL_DEF_APN, QAPI_DSS_CALL_INFO_PASSWORD_MAX_LEN ); */

	demo3_network_config_data(apn, apn_username, apn_passwd);


    //qt_uart_dbg(uart1_conf.hdlr,"------------Setting tech to Automatic\n %s", apn);                                                                              
    if (NULL != tcp_dss_handle_dns)
    {
        /* set data call param */
        param_info.buf_val = NULL;
        param_info.num_val = QAPI_DSS_RADIO_TECH_LTE;   /*Automatic mode(or DSS_RADIO_TECH_LTE) */
        qt_uart_dbg(uart1_conf.hdlr,"Setting tech to Automatic\n");
        qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_TECH_PREF_E, &param_info);

		param_info.buf_val = NULL; //(char*)&val;
        param_info.num_val = QAPI_DSS_AUTH_PREF_PAP_CHAP_NOT_ALLOWED_E;//sizeof(val);	//Automatic mode(or DSS_RADIO_TECH_LTE)
        qt_uart_dbg(uart1_conf.hdlr,"Setting tech to Auth to NONE\n");
        qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_AUTH_PREF_E, &param_info);

        /* set apn */
        param_info.buf_val = apn;
        param_info.num_val = strlen(apn);
        qt_uart_dbg(uart1_conf.hdlr,"Setting APN - %s\n", apn);
        qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_APN_NAME_E, &param_info);

#if 0
//#ifdef QUEC_CUSTOM_APN                                                           
        /* set apn username */
		if(strlen(apn_username)) 
		{
			param_info.buf_val = apn_username;
			param_info.num_val = strlen(apn_username);
			qt_uart_dbg(uart1_conf.hdlr,"Setting APN USER - %s\n", apn_username);
			qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_USERNAME_E, &param_info);
																					
			/* set apn password */                                                   
			param_info.buf_val = apn_passwd;                                         
			param_info.num_val = strlen(apn_passwd);                                 
			qt_uart_dbg(uart1_conf.hdlr,"Setting APN PASSWORD - %s\n", apn_passwd);                
			qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_PASSWORD_E, &param_info);
		}

//#endif
#endif

        /* set IP version(IPv4 or IPv6) */
        param_info.buf_val = NULL;                                               
        param_info.num_val = QAPI_DSS_IP_VERSION_4;                              
        qt_uart_dbg(uart1_conf.hdlr,"Setting family to IPv%d\n", param_info.num_val);          
        qapi_DSS_Set_Data_Call_Param(tcp_dss_handle_dns, QAPI_DSS_CALL_INFO_IP_VERSION_E, &param_info);
    }                                                                            
    else                                                                         
    {                                                                            
        qt_uart_dbg(uart1_conf.hdlr,"Dss handler is NULL!!!");                               
        return -1;                                                               
    }                                                                            
                                                                                 
    return 0;                                                                    
}

/*                                                                               
@func                                                                            
    tcp_inet_ntoa                                                                
@brief                                                                           
    utility interface to translate ip from "int" to x.x.x.x format.              
*/                                                                               
int32 tcp_inet_ntoa                                                              
(                                                                                
    const qapi_DSS_Addr_t    inaddr, /* IPv4 address to be converted         */  
    uint8                   *buf,    /* Buffer to hold the converted address */  
    int32                    buflen  /* Length of buffer                     */  
)                                                                                
{                                                                                
    uint8 *paddr  = (uint8 *)&inaddr.addr.v4;                                    
    int32  rc = 0;                                                               
                                                                                 
    if ((NULL == buf) || (0 >= buflen))                                          
    {                                                                            
        rc = -1;                                                                 
    }                                                                            
    else                                                                         
    {                                                                            
        if (-1 == snprintf((char*)buf, (unsigned int)buflen, "%d.%d.%d.%d",      
                            paddr[0],                                            
                            paddr[1],                                            
                            paddr[2],                                            
                            paddr[3]))                                           
        {                                                                        
            rc = -1;                                                             
        }                                                                        
    }                                                                            
                                                                                 
    return rc;                                                                   
} /* tcp_inet_ntoa() */                                                          
  

void tcp_show_sysinfo(void)
{
	int i   = 0;
	int j 	= 0;
	unsigned int len = 0;
	uint8 buff[DSS_ADDR_SIZE] = {0}; 
	qapi_Status_t status;
	qapi_DSS_Addr_Info_t info_ptr[DSS_ADDR_INFO_SIZE];

	status = qapi_DSS_Get_IP_Addr_Count(tcp_dss_handle_dns, &len);
	if (QAPI_ERROR == status)
	{
		qt_uart_dbg(uart1_conf.hdlr,"Get IP address count error");
		return;
	}
		
	status = qapi_DSS_Get_IP_Addr(tcp_dss_handle_dns, info_ptr, len);
	if (QAPI_ERROR == status)
	{
		qt_uart_dbg(uart1_conf.hdlr,"Get IP address error with status [%d]",status);
		return;
	}

	j = GET_ADDR_INFO_MIN(len, DSS_ADDR_INFO_SIZE);

	for (i = 0; i < j; i++)
	{
		qt_uart_dbg(uart1_conf.hdlr,"<--- static IP address information --->");
		tcp_inet_ntoa(info_ptr[i].iface_addr_s, buff, DSS_ADDR_SIZE);
		qt_uart_dbg(uart1_conf.hdlr,"static IP: %s",buff);

		memset(buff, 0, sizeof(buff));
		tcp_inet_ntoa(info_ptr[i].gtwy_addr_s, buff, DSS_ADDR_SIZE);
		qt_uart_dbg(uart1_conf.hdlr,"Gateway IP: %s",buff);

		memset(buff, 0, sizeof(buff));
		tcp_inet_ntoa(info_ptr[i].dnsp_addr_s, buff, DSS_ADDR_SIZE);
		qt_uart_dbg(uart1_conf.hdlr,"Primary DNS IP: %s",buff);

		memset(buff, 0, sizeof(buff));
		tcp_inet_ntoa(info_ptr[i].dnss_addr_s, buff, DSS_ADDR_SIZE);
		qt_uart_dbg(uart1_conf.hdlr,"Second DNS IP: %s",buff);
	}

	qt_uart_dbg(uart1_conf.hdlr,"<--- End of system info --->");
}

/*
@func
	dss_net_event_cb
@brief
	Initializes the DSS netctrl library for the specified operating mode.
*/

static void tcp_net_event_cb
( 
	qapi_DSS_Hndl_t 		hndl,
	void 				   *user_data,
	qapi_DSS_Net_Evt_t 		evt,
	qapi_DSS_Evt_Payload_t *payload_ptr 
)
{
	qapi_Status_t status = QAPI_OK;
	
	qt_uart_dbg(uart1_conf.hdlr,"Data test event callback, event: %d\n", evt);

	switch (evt)
	{
		case QAPI_DSS_EVT_NET_IS_CONN_E:
		{
			qt_uart_dbg(uart1_conf.hdlr,"Data Call Connected.");
			tcp_show_sysinfo();
			/* Signal main task */
  			tx_event_flags_set(&tcp_signal_handle, DSS_SIG_EVT_CONN_E, TX_OR);
			tcp_datacall_status = DSS_EVT_NET_IS_CONN_E;
			mqtt_init_flag = 1;

			break;
		}
		case QAPI_DSS_EVT_NET_NO_NET_E:
		{
			qt_uart_dbg(uart1_conf.hdlr,"Data Call Disconnected.");
			mqtt_init_flag = 2;
			
			if (DSS_EVT_NET_IS_CONN_E == tcp_datacall_status)
			{
				/* Release Data service handle and netctrl library */
				if (tcp_dss_handle_dns)
				{
					status = qapi_DSS_Rel_Data_Srvc_Hndl(tcp_dss_handle_dns);
					if (QAPI_OK == status)
					{
						qt_uart_dbg(uart1_conf.hdlr,"Release data service handle success");
						tx_event_flags_set(&tcp_signal_handle, DSS_SIG_EVT_EXIT_E, TX_OR);
					}
				}
				if (DSS_LIB_STAT_SUCCESS_E == tcp_netctl_lib_status)
				{
					qapi_DSS_Release(QAPI_DSS_MODE_GENERAL);
				}
			}
			else
			{
				tx_event_flags_set(&tcp_signal_handle, DSS_SIG_EVT_NO_CONN_E, TX_OR);
			}
			break;
		}
		default:
		{
			qt_uart_dbg(uart1_conf.hdlr,"Data Call status is invalid.");
			mqtt_init_flag = 3;

			/* Signal main task */
  			tx_event_flags_set(&tcp_signal_handle, DSS_SIG_EVT_INV_E, TX_OR);
			tcp_datacall_status = DSS_EVT_INVALID_E;
			break;
		}
	}
}

/*
@func
	tcp_netctrl_init
@brief
	Initializes the DSS netctrl library for the specified operating mode.
*/

static int tcp_netctrl_init(void)
{
	int ret_val = 0;
	qapi_Status_t status = QAPI_OK;

	qt_uart_dbg(uart1_conf.hdlr,"Initializes the DSS netctrl library");

	/* Initializes the DSS netctrl library */
	if (QAPI_OK == qapi_DSS_Init(QAPI_DSS_MODE_GENERAL))
	{
		tcp_netctl_lib_status = DSS_LIB_STAT_SUCCESS_E;
		qt_uart_dbg(uart1_conf.hdlr,"qapi_DSS_Init success");
	}
	else
	{
		/* @Note: netctrl library has been initialized */
		tcp_netctl_lib_status = DSS_LIB_STAT_FAIL_E;
		qt_uart_dbg(uart1_conf.hdlr,"DSS netctrl library has been initialized");
	}

	/* Registering callback tcp_dss_handleR */
	do
	{
		qt_uart_dbg(uart1_conf.hdlr,"Registering Callback tcp_dss_handle");

		/* Obtain data service handle */
		status = qapi_DSS_Get_Data_Srvc_Hndl(tcp_net_event_cb, NULL, &tcp_dss_handle_dns);
		qt_uart_dbg(uart1_conf.hdlr,"tcp_dss_handle_dns %d, status %d", tcp_dss_handle_dns, status);

		if (NULL != tcp_dss_handle_dns)
		{
			qt_uart_dbg(uart1_conf.hdlr,"Registed tcp_dss_handler success");
			break;
		}
		/* Obtain data service handle failure, try again after 10ms */
		qapi_Timer_Sleep(10, QAPI_TIMER_UNIT_MSEC, true);
	} while(1);
	return ret_val;
}

/*
@func
	tcp_netctrl_start
@brief
	Start the DSS netctrl library, and startup data call.
*/

int tcp_netctrl_start(void)
{
	int rc = 0;
	qapi_Status_t status = QAPI_OK;
	
	rc = tcp_netctrl_init();
	if (0 == rc)
	{
		/* Get valid DSS handler and set the data call parameter */
		//tcp_set_data_param();
		qt_uart_dbg(uart1_conf.hdlr,"quectel_dss_init pass");
	}
	else
	{
		qt_uart_dbg(uart1_conf.hdlr,"quectel_dss_init fail");
		return -1;
	}
	qt_uart_dbg(uart1_conf.hdlr,"qapi_DSS_Start_Data_Call start!!!");
	
	status = qapi_DSS_Start_Data_Call(tcp_dss_handle_dns);
	if (QAPI_OK == status)
	{
		qt_uart_dbg(uart1_conf.hdlr,"Start Data service success.");
		/*set a flag to start with mqtt_init*/
		return 0;
	}
	else
	{
		return -1;
	}
}

//config data format : "apn|username|password"..only username format "apn|"
static int demo3_network_config_data(char *apn, char *username, char *password)
{
	uint32 bytes_read;
	int efs_fd = QAPI_ERROR;
	struct qapi_FS_Stat_Type_s stat = {0};
	uint8_t *file_buf = NULL;
	char *ptr, *ptr1;


	if(qapi_FS_Open("/datatx/demo3.cfg", QAPI_FS_O_RDONLY_E, &efs_fd) < 0) 
	{
		qt_uart_dbg(uart1_conf.hdlr,"Opening config EFS file failed\n");
		return QAPI_ERROR;
	}

	memset( &stat, 0, sizeof(struct qapi_FS_Stat_Type_s )); 
	if(qapi_FS_Stat_With_Handle(efs_fd, &stat) < 0) 
	{
		qt_uart_dbg(uart1_conf.hdlr,"Reading config EFS file failed\n");
		return QAPI_ERROR;
	}

	//file_buf = ges_mem_alloc(stat.st_size + 4); /*Added 4 bytes extra for padding*/
	tx_byte_allocate( &g_tx_byte_pool, (VOID **)(&file_buf), (stat.st_size + 1), TX_NO_WAIT);   

	if(file_buf == NULL) 
	{
		qt_uart_dbg(uart1_conf.hdlr," filebuf mem_alloc failed \n");
		return QAPI_ERROR;
	}

	file_buf[stat.st_size] = 0;

	qapi_FS_Read(efs_fd, file_buf, stat.st_size, &bytes_read);
	if(bytes_read != stat.st_size)
	{
		tx_byte_release(file_buf);
		qt_uart_dbg(uart1_conf.hdlr,"Reading EFS file error\n");
		return QAPI_ERROR;
	}

	qapi_FS_Close(efs_fd);

	ptr = strstr(file_buf, "|");
	if(ptr)
	{
		*ptr = 0;
		strcpy(apn, file_buf);
		ptr++;
		ptr1 = strstr(ptr, "|");
		if(ptr1)
		{
			*ptr1 = 0;
			strcpy(username, ptr);
			ptr1++;
			strcpy(password, ptr1);
		}
	}

	qt_uart_dbg(uart1_conf.hdlr,"Read apn %s\n", apn);
	qt_uart_dbg(uart1_conf.hdlr,"Read username %s\n", username);
	qt_uart_dbg(uart1_conf.hdlr,"Read password %s\n", password);


	tx_byte_release(file_buf);

	return QAPI_OK;
}



extern void create_timer_thread();

//bool infinitePublishFlag = true;
char rootCA[PATH_MAX + 1];
char clientCRT[PATH_MAX + 1];
char clientKey[PATH_MAX + 1];
//char CurrentWD[PATH_MAX + 1];
char cPayload[CMD_BUF_SIZE];

/*
@func
	aws_sub_pub_appl
@brief
	Start the data call and initialises the mqtt.
*/

int aws_sub_pub_appl() {

	UINT status = 0;
	TASK_COMM qt_sub1_task_comm;
	AWS_IoT_Client client;
	IoT_Client_Init_Params mqttInitParams;
	IoT_Client_Connect_Params connectParams;
	IoT_Publish_Message_Params paramsQOS0;
	//IoT_Publish_Message_Params paramsQOS1;
	int32_t i = 0;
	IoT_Error_t rc = 0;


	/*  data call implementation */
	mqtt_init_flag = 0;	/* set the flag when the data session is started */
	tcp_netctrl_start();

	while(!mqtt_init_flag)
	{
		qt_uart_dbg(uart1_conf.hdlr,"waiting for connection");
		qapi_Timer_Sleep(2, QAPI_TIMER_UNIT_SEC, true);
	}

	if(mqtt_init_flag == 2)
	{
		qt_uart_dbg(uart1_conf.hdlr,"can't connect");
		return 0;
	}

	if(mqtt_init_flag == 3)
	{
		qt_uart_dbg(uart1_conf.hdlr," invalid connection");
		return 0;
	}


	mqttInitParams = iotClientInitParamsDefault;
	connectParams = iotClientConnectParamsDefault;

	qt_uart_dbg(uart1_conf.hdlr,"loading certificates and parameters");

	snprintf(rootCA, PATH_MAX + 1, "%s/%s",  certDirectory, AWS_IOT_ROOT_CA_FILENAME);
	snprintf(clientCRT, PATH_MAX + 1, "%s/%s", certDirectory, AWS_IOT_CERTIFICATE_FILENAME);
	snprintf(clientKey, PATH_MAX + 1, "%s/%s",  certDirectory, AWS_IOT_PRIVATE_KEY_FILENAME);

    //qt_uart_dbg(uart1_conf.hdlr,"rootCA %s", rootCA);
    qt_uart_dbg(uart1_conf.hdlr,"clientCRT %s", clientCRT);
    qt_uart_dbg(uart1_conf.hdlr,"clientKey %s", clientKey);

	mqttInitParams.enableAutoReconnect = false; /* We will enable this later below */
	mqttInitParams.pHostURL = HostAddress;
	mqttInitParams.port = port;
	mqttInitParams.pRootCALocation = rootCA;
	mqttInitParams.pDeviceCertLocation = clientCRT;
	mqttInitParams.pDevicePrivateKeyLocation = clientKey;
	mqttInitParams.mqttCommandTimeout_ms = 10000;
	mqttInitParams.tlsHandshakeTimeout_ms = 5000;
	mqttInitParams.isSSLHostnameVerify = true;	/*should to be true*/
	mqttInitParams.disconnectHandler = disconnectCallbackHandler;
	mqttInitParams.disconnectHandlerData = NULL;

	qt_uart_dbg(uart1_conf.hdlr,"calling mqtt init");



	{ /*once data cal is successful then enter	*/

		rc = aws_iot_mqtt_init(&client, &mqttInitParams);
		qt_uart_dbg(uart1_conf.hdlr,"aws_iot_mqtt_init [%d]", rc);
		if(SUCCESS != rc) 
		{
				IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
				qt_uart_dbg(uart1_conf.hdlr,"aws_iot_mqtt_init returned error : %d ", rc);
				return rc;
		}

		connectParams.keepAliveIntervalInSec = 600;
		connectParams.isCleanSession = true;
		connectParams.MQTTVersion = MQTT_3_1_1;
		connectParams.pClientID = AWS_IOT_MQTT_CLIENT_ID;
		connectParams.clientIDLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
		connectParams.isWillMsgPresent = false;

		qt_uart_dbg(uart1_conf.hdlr,"Connecting");
		rc = aws_iot_mqtt_connect(&client, &connectParams);
		if(SUCCESS != rc) 
		{
			qt_uart_dbg(uart1_conf.hdlr,"error in connection");
			return rc;
		}

		qt_uart_dbg(uart1_conf.hdlr,"Connect is done");
		
		/* Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
		*  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
		*  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
		*/
		rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
		if(SUCCESS != rc) 
		{
			qt_uart_dbg(uart1_conf.hdlr,"Unable to set Auto Reconnect to true - %d", rc);
			return rc;
		}
	
		paramsQOS0.qos = QOS0;
		paramsQOS0.payload = (void *) cPayload;
		paramsQOS0.isRetained = 0;

		create_timer_thread();
		//rc = 0;
	
		while(NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc) 
		{
			  
			memset(&qt_sub1_task_comm, 0, sizeof(qt_sub1_task_comm));

			/* rec data from main task by queue */
			status = tx_queue_receive(&tx_queue_handle, &qt_sub1_task_comm, TX_WAIT_FOREVER);

			if(TX_SUCCESS != status)
			{
				qt_uart_dbg(uart1_conf.hdlr, "[task_create] tx_queue_receive failed with status %d", status);
				//sub1_thread_run_couter = 0;
			}

			/*Max time the yield function will wait for read messages */
			qt_uart_dbg(uart1_conf.hdlr,"calling aws_iot_mqtt_yield");

			if(qt_sub1_task_comm.type == AWS_TIMER)
			{
				rc = aws_iot_mqtt_yield(&client, 100);
				qt_uart_dbg(uart1_conf.hdlr,"aws_iot_mqtt_yield returned [%d]",rc);
				if(NETWORK_ATTEMPTING_RECONNECT == rc) {
					/* If the client is attempting to reconnect we will skip the rest of the loop. */
					continue;
				}
			}
			else
			{
				qt_uart_dbg(uart1_conf.hdlr,"-->sleep");
				//qapi_Timer_Sleep(2, QAPI_TIMER_UNIT_SEC, true);
				sprintf(cPayload, "%d : %d ", qt_sub1_task_comm.data, i++);
				qt_uart_dbg(uart1_conf.hdlr,"hello");
				qt_uart_dbg(uart1_conf.hdlr,"calling aws_iot_mqtt_publish");
				paramsQOS0.payloadLen = strlen(cPayload);
				rc = aws_iot_mqtt_publish(&client, "inventory_update", 16, &paramsQOS0);
				qt_uart_dbg(uart1_conf.hdlr,"aws_iot_mqtt-publish returned [%d]",rc);
			}
		}

		if(SUCCESS != rc) 
		{
			qt_uart_dbg(uart1_conf.hdlr,"An error occurred in the loop");
		
		} else 
		{
			qt_uart_dbg(uart1_conf.hdlr,"publish done");
		}
	}

	qt_uart_dbg(uart1_conf.hdlr,"exiting subscribe function");
	qapi_Timer_Sleep(10, QAPI_TIMER_UNIT_SEC, true);
	return rc;
}

int quectel_aws_task_entry(void)
{

	qapi_Timer_Sleep(SLEEP_TIME, QAPI_TIMER_UNIT_SEC, true);
	/* uart 1 init */
	//uart_init(&uart1_conf);

	/* start uart 1 receive */
	//uart_recv(&uart1_conf);

	/* prompt task running */
	qt_uart_dbg(uart1_conf.hdlr,"[task_create] start task ~");

    // to create the pool memory
	status = tx_byte_pool_create(&g_tx_byte_pool, "my_byte_pool",g_tx_byte_pool_area ,BYTE_POOL_SIZE);

	if (status != TX_SUCCESS){
		qt_uart_dbg(uart1_conf.hdlr,"byte pool creation failed");
	}
	qt_uart_dbg(uart1_conf.hdlr,"main thread started");
	
	aws_sub_pub_appl();

	qt_uart_dbg(uart1_conf.hdlr,"sleep timer for 15 sec");
	qapi_Timer_Sleep(SLEEP_TIME, QAPI_TIMER_UNIT_SEC, true);
	return 0;
}


