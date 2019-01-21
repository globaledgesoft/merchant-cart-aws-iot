/*
 * COPYRIGHTS
 */

 
#ifdef __cplusplus
extern "C" {
#endif

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
#include "qapi_diag.h"
#include "txm_module.h"
#include "qapi_dss.h"
#include "qapi_netservices.h"
#include "qapi_socket.h"
#include "qapi_net_status.h"
#include "network_platform.h"
#include "network_interface.h"
#include "qapi_dnsc.h"
#include "aws_iot_error.h"
#include "aws_iot_config.h"
#include "aws_iot_log.h"

#include "stringl/stringl.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>


#define _htons(x)           ((unsigned short)((((unsigned short)(x) & 0x00ff) << 8) | (((unsigned short)(x) & 0xff00) >> 8)))
#define _ntohs(x)           ((unsigned short)((((unsigned short)(x) & 0x00ff) << 8) | (((unsigned short)(x) & 0xff00) >> 8)))

/* This defines the value of the debug buffer that gets allocated.
 * The value can be altered based on memory constraints
 */
#ifdef ENABLE_IOT_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#endif

#define IOT_TRUE    ((bool)1)
#define IOT_FALSE   ((bool)0)
#define IOT_STRNCPY strncpy


/***************************************************************************/
//#define QL_DEF_APN          "airtelgprs.com"
#define DSS_ADDR_INFO_SIZE  5
#define DSS_ADDR_SIZE       16
#define GET_ADDR_INFO_MIN(a, b) ((a) > (b) ? (b) : (a))

#if 1
#define TS_CLIENT_CERT_PEM "QCA4020_MUSIC_FTV.cert.pem"
#define TS_CLIENT_CERT_KEY_PEM "QCA4020_MUSIC_FTV.private.key"
#define TS_CLIENT_CERT_STORE_CERT "QCA4020_MUSIC_FTV.bin"
#define TS_CLIENT_CERT_STORE_CA "root-CA.bin"
#define TS_CLIENT_CA_LIST_PEM "root-CA.crt"
#endif

#define ESUCCESS 0
#define EFAILURE -1
/**************************************************************************
*                                 GLOBAL
***************************************************************************/
qapi_Net_MQTT_Hndl_t    app_mqttcli_ctx = NULL;
qapi_Net_MQTT_Config_t  mqttdemo_cfg;

/*===========================================================================

                           Static & global Variable Declarations

===========================================================================*/

extern qapi_DSS_Hndl_t tcp_dss_handle_dns; 

extern TX_BYTE_POOL g_tx_byte_pool;
extern UINT status;

/* Uart Dbg */
extern QT_UART_CONF_PARA uart1_conf;                                                                                

qapi_DSS_Hndl_t tdcp_dss_handle = NULL;             /* Related to DSS netctrl */

struct ip46addr ipaddr;


/* network interface wrapper API definition */
/*******************************************************************************
 * SDK MQTT functions
 * *****************************************************************************/
 
/**
 * @brief Read Cert files from EFS
 * @param name File name
 * @param buffer_ptr File buffer
 * @param buffer_size Buffer size
 * @return QAPI_OK or QAPI_ERROR
 */
static int cert_read_from_EFS_file(
    const char * name,
    void ** buffer_ptr,
    size_t * buffer_size
    )
{
  uint32 bytes_read;
  int efs_fd = QAPI_ERROR;
  struct qapi_FS_Stat_Type_s stat = {0};
  uint8_t *file_buf = NULL;

  if((!name) || (!buffer_ptr) || (!buffer_size)) {
    return QAPI_ERROR;
  }
   
  memset( &stat, 0, sizeof(struct qapi_FS_Stat_Type_s )); 
  if(qapi_FS_Open(name, QAPI_FS_O_RDONLY_E, &efs_fd) < 0) {
    qt_uart_dbg(uart1_conf.hdlr,"Opening EFS file %s failed\n", name);
    return QAPI_ERROR;
  }

  if(qapi_FS_Stat_With_Handle(efs_fd, &stat) < 0) {
    qt_uart_dbg(uart1_conf.hdlr,"Reading EFS file %s failed\n", name);
    return QAPI_ERROR;
  }

  qt_uart_dbg(uart1_conf.hdlr,"Reading EFS file size %d \n", stat.st_size);


  //file_buf = ges_mem_alloc(stat.st_size + 4); /*Added 4 bytes extra for padding*/
 tx_byte_allocate( &g_tx_byte_pool, (VOID **)(&file_buf), (stat.st_size + 4), TX_NO_WAIT);   

  if(file_buf == NULL) {
    qt_uart_dbg(uart1_conf.hdlr,"ges_mem_alloc failed \n");
    return QAPI_ERROR;
  }

  qapi_FS_Read(efs_fd, file_buf, stat.st_size, &bytes_read);
  if(bytes_read != stat.st_size) {
    tx_byte_release(file_buf);
    qt_uart_dbg(uart1_conf.hdlr,"Reading EFS file error\n");
    return QAPI_ERROR;
  }

  *buffer_ptr = file_buf;
  *buffer_size = stat.st_size;

  qapi_FS_Close(efs_fd);

  return QAPI_OK;
}


/**
 * @brief Check if cert is present in SecureFS
 * @param type Type of cerficate
 * @param file_name File name
 */
static void ges_ssl_check_and_store_cerges(qapi_Net_SSL_Cert_Type_t type, const char *file_name)
{

  void* ca_buf     = NULL;
  void* cert_buf   = NULL;
  void* key_buf    = NULL;
  
  size_t ca_buf_size   = 0;
  size_t cert_buf_size = 0;
  size_t key_buf_size  = 0;
  qapi_Status_t ret    = 0;

  qapi_Net_SSL_Cert_Info_t cert_info;
  
  if(file_name == NULL)
    return;
  
  memset(&cert_info, 0, sizeof(qapi_Net_SSL_Cert_Info_t));

  if(type == QAPI_NET_SSL_CERTIFICATE_E) {

    if(cert_read_from_EFS_file("/datatx/"TS_CLIENT_CERT_PEM, &cert_buf, &cert_buf_size) < QAPI_OK)
      return;
    
    if(cert_read_from_EFS_file("/datatx/"TS_CLIENT_CERT_KEY_PEM, &key_buf, &key_buf_size) < QAPI_OK)
      return;
    
    if((cert_buf == NULL) || (key_buf == NULL)) {
      qt_uart_dbg(uart1_conf.hdlr,"Failed load cert and key from EFS\n");
      goto err;
    }

    cert_info.cert_Type = QAPI_NET_SSL_CERTIFICATE_E;
    cert_info.info.cert.cert_Buf = cert_buf;
    cert_info.info.cert.cert_Size = cert_buf_size;
    cert_info.info.cert.key_Buf = key_buf;
    cert_info.info.cert.key_Size = key_buf_size;
    cert_info.info.cert.pass_Key = NULL;
    
    qapi_Net_SSL_Cert_delete((char *)file_name, QAPI_NET_SSL_CERTIFICATE_E);
    
    ret = qapi_Net_SSL_Cert_Convert_And_Store(&cert_info,
                                              (const uint8_t *)file_name);

    if(ret != QAPI_OK) {
      qt_uart_dbg(uart1_conf.hdlr," Failed to store %s : %d\n", file_name, ret);
    } else {
      qt_uart_dbg(uart1_conf.hdlr," Loaded Cert and Key successfully\n");
      qapi_FS_Truncate("/datatx/"TS_CLIENT_CERT_PEM, 0);
      qapi_FS_Unlink("/datatx/"TS_CLIENT_CERT_PEM);
      qapi_FS_Truncate("/datatx/"TS_CLIENT_CERT_KEY_PEM, 0);
      qapi_FS_Unlink("/datatx/"TS_CLIENT_CERT_KEY_PEM);
    }

  err:
    if(cert_info.info.cert.cert_Buf != NULL)
      tx_byte_release(cert_info.info.cert.cert_Buf);
    if(cert_info.info.cert.key_Buf != NULL)
      tx_byte_release(cert_info.info.cert.key_Buf);

  } else {
    
    if(cert_read_from_EFS_file("/datatx/"TS_CLIENT_CA_LIST_PEM, &ca_buf, &ca_buf_size) < QAPI_OK)
      return;
      
    if(ca_buf != NULL) {

      cert_info.cert_Type = QAPI_NET_SSL_CA_LIST_E;
      cert_info.info.ca_List.ca_Cnt = 1;
    //cert_info.info.ca_List.ca_Info[0] = ges_mem_alloc(sizeof(qapi_NET_SSL_CA_Info_t));
      tx_byte_allocate( &g_tx_byte_pool, (VOID **)(&cert_info.info.ca_List.ca_Info[0]),sizeof(qapi_NET_SSL_CA_Info_t) , TX_NO_WAIT);
 
      qapi_Net_SSL_Cert_delete((char *)file_name, QAPI_NET_SSL_CA_LIST_E);
       
      if(cert_info.info.ca_List.ca_Info[0] != NULL) {

        cert_info.info.ca_List.ca_Info[0]->ca_Buf = ca_buf;
        cert_info.info.ca_List.ca_Info[0]->ca_Size = ca_buf_size;

        ret = qapi_Net_SSL_Cert_Convert_And_Store(&cert_info,
                                                  (const uint8_t *)file_name);

        if(ret != QAPI_OK) {
          qt_uart_dbg(uart1_conf.hdlr," Failed to store %s : %d\n", file_name, ret);
        } else {
          qt_uart_dbg(uart1_conf.hdlr," Loaded CA list successfully\n");
          qapi_FS_Truncate("/datatx/"TS_CLIENT_CA_LIST_PEM, 0);
          qapi_FS_Unlink("/datatx/"TS_CLIENT_CA_LIST_PEM);
        }

        if(cert_info.info.ca_List.ca_Info[0]->ca_Buf != NULL)
          tx_byte_release(cert_info.info.ca_List.ca_Info[0]->ca_Buf);

        tx_byte_release(cert_info.info.ca_List.ca_Info[0]);
        
      }
	 else{
		qt_uart_dbg(uart1_conf.hdlr,"Failed to allocate mem for list CA\n");
	}
    }
  }
}


void ges_ssl_load_cerges()
{
  qapi_Net_SSL_Obj_Hdl_t ssl_hndl;
  
  ssl_hndl = qapi_Net_SSL_Obj_New(QAPI_NET_SSL_CLIENT_E);
  
  if(ssl_hndl != NULL) {
	qt_uart_dbg(uart1_conf.hdlr,"SSL handler obtained\n");
    ges_ssl_check_and_store_cerges(QAPI_NET_SSL_CERTIFICATE_E, TS_CLIENT_CERT_STORE_CERT);
//    ges_ssl_check_and_store_cerges(QAPI_NET_SSL_CA_LIST_E, TS_CLIENT_CERT_STORE_CA);
    qapi_Net_SSL_Obj_Free(ssl_hndl);
  } else {
   qt_uart_dbg(uart1_conf.hdlr, "Failed start SSL\n");
  }
}


IoT_Error_t iot_tls_write(
	Network *pNetwork, 
	unsigned char *pMsg, 
	size_t len, 
	Timer *timer, 
	size_t *written_len)
{
	size_t written_so_far;
	bool isErrorFlag = false;
	int frags;
	int ret = 0;
	TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);

    qt_uart_dbg(uart1_conf.hdlr,"inside iot_tls_write");
	for(written_so_far = 0, frags = 0;
		written_so_far < len && !has_timer_expired(timer); written_so_far += ret, frags++) {
		while(!has_timer_expired(timer) &&
			  (ret = qapi_Net_SSL_Write( tlsDataParams->hConn, pMsg + written_so_far, len - written_so_far)) <= 0) {
			if(ret != QAPI_OK ) {
				IOT_ERROR(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
				/* All other negative return values indicate connection needs to be reset.
		 		* Will be caught in ping request so ignored here */
				isErrorFlag = true;
				break;
			}
		}
		if(isErrorFlag) {
			break;
		}
	}

	*written_len = written_so_far;

	if(isErrorFlag) {
		return NETWORK_SSL_WRITE_ERROR;
	} else if(has_timer_expired(timer) && written_so_far != len) {
		return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
	}

    qt_uart_dbg(uart1_conf.hdlr,"exiting iot_tls_write");
	return SUCCESS;
}

IoT_Error_t iot_tls_is_connected(Network *pNetwork)
{
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    
    qt_uart_dbg(uart1_conf.hdlr,"inside iot_tls_connected");
    /* TODO: Need to check if there is a interface available to check SSL sate*/
    qt_uart_dbg(uart1_conf.hdlr,"exiting iot_tls_connected");
	return NETWORK_PHYSICAL_LAYER_CONNECTED;
}

IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *TLSParams)
{
    int e, i, j = 0;
    int32_t family = AF_INET;
    struct sockaddr_in addr = {0};
	char *dns_ip;
	char iface[15] = {0};
    int32_t res = 0;
    int32_t res1 = 0;
    unsigned int len = 0;
	char ip_str[48];
    char first_dns[DSS_ADDR_SIZE] = {0};
    char second_dns[DSS_ADDR_SIZE] = {0};

    qapi_DSS_Addr_Info_t info_ptr[DSS_ADDR_INFO_SIZE];
    IoT_Error_t result = FAILURE;
    qapi_Status_t status;

    ipaddr.type = AF_INET; 

    qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsConnectParams.pRootCALocation [%s]",
									pNetwork->tlsConnectParams.pRootCALocation);
    qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsConnectParams.pDeviceCertLocation [%s]",
									pNetwork->tlsConnectParams.pDeviceCertLocation);
    qt_uart_dbg(uart1_conf.hdlr,"need memory allocation\n");

    memset(&(pNetwork->tlsDataParams),0,sizeof(pNetwork->tlsDataParams));
	/* memset for the dataparameters */

	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.domain = [%d] , is should be 1",
								pNetwork->tlsDataParams.sConf.verify.domain);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.send_Alert = [%d] is should be 1",
								pNetwork->tlsDataParams.sConf.verify.send_Alert);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.time_Validity = [%d] is shoul;d be 1",
								pNetwork->tlsDataParams.sConf.verify.time_Validity);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.max_Frag_Len = [%d]", 
								pNetwork->tlsDataParams.sConf.max_Frag_Len);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.max_Frag_Len_Neg_Disable = [%d]",
								pNetwork->tlsDataParams.sConf.max_Frag_Len_Neg_Disable);
    
	qt_uart_dbg(uart1_conf.hdlr,"inside connect2\n"); 
    /* ~~Parameter checks before continuing further with SSL connection creation~~ */
    qt_uart_dbg(uart1_conf.hdlr,"TLS Params initailized1\n");
    if (NULL == pNetwork){
        qt_uart_dbg(uart1_conf.hdlr,"connect failed with NULL_VALUE_ERROR\n");
		qt_uart_dbg(uart1_conf.hdlr,"Suspected\n");
        return NULL_VALUE_ERROR;
    }
	qt_uart_dbg(uart1_conf.hdlr,"Suspect un-confirmed\n");
    if (NULL != TLSParams){
        pNetwork->tlsConnectParams = *TLSParams; 
        qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsConnectParams = *TLSParams;");
    }

    qt_uart_dbg(uart1_conf.hdlr,"TLS Params initailized2");
    qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsConnectParams.pRootCALocation [%s]",
								pNetwork->tlsConnectParams.pRootCALocation);

    qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsConnectParams.pDeviceCertLocation [%s]",
								pNetwork->tlsConnectParams.pDeviceCertLocation);
    
    if (NULL == pNetwork->tlsConnectParams.pRootCALocation || NULL == pNetwork->tlsConnectParams.pDeviceCertLocation){
        qt_uart_dbg(uart1_conf.hdlr,"connect failed with NETWORK_SSL_CERT_ERROR");   
        return NETWORK_SSL_CERT_ERROR;
    }
#if 1	/* DNS resolver*/	
    /* Get DNS server address */
    status = qapi_DSS_Get_IP_Addr_Count(tcp_dss_handle_dns, &len);
    if (QAPI_ERROR == status) {
		qt_uart_dbg(uart1_conf.hdlr,"Get IP address count error [%d]",status);
        return;
    }

    status = qapi_DSS_Get_IP_Addr(tcp_dss_handle_dns, info_ptr, len);
    if (QAPI_ERROR == status) {
        qt_uart_dbg(uart1_conf.hdlr,"Get IP address error [%d]",status);
        return;
    }
	/* DNS Resolution*/ 
    j = GET_ADDR_INFO_MIN(len, DSS_ADDR_INFO_SIZE);
    qt_uart_dbg(uart1_conf.hdlr,"@@@j = %d\n", j);

    for (i = 0; i < j; i++) {
        memset(first_dns, 0, sizeof(first_dns));
        tcp_inet_ntoa(info_ptr[i].dnsp_addr_s, (uint8*)first_dns, DSS_ADDR_SIZE);
        qt_uart_dbg(uart1_conf.hdlr,"Primary DNS IP: %s\n", first_dns);

        memset(second_dns, 0, sizeof(second_dns));
        tcp_inet_ntoa(info_ptr[i].dnss_addr_s, (uint8*)second_dns, DSS_ADDR_SIZE);
        qt_uart_dbg(uart1_conf.hdlr,"Second DNS IP: %s\n", second_dns);
    }

	/* Start DNS service */
    e = qapi_Net_DNSc_Command(QAPI_NET_DNS_START_E);
    qt_uart_dbg(uart1_conf.hdlr,"Start DNSc.........");

    /* Get current active iface */
    memset(iface, 0, sizeof(iface));
    qapi_DSS_Get_Device_Name(tcp_dss_handle_dns, iface, 15);
    qt_uart_dbg(uart1_conf.hdlr,"device_name: %s\n", iface);

    /* Add dns server into corresponding interface */
    qapi_Net_DNSc_Add_Server_on_iface(first_dns, QAPI_NET_DNS_V4_PRIMARY_SERVER_ID, iface);
    qapi_Net_DNSc_Add_Server_on_iface(second_dns, QAPI_NET_DNS_V4_SECONDARY_SERVER_ID, iface);

    /* URL parser */
	e = qapi_Net_DNSc_Reshost_on_iface(pNetwork->tlsConnectParams.pDestinationURL, &ipaddr, iface);

    if (e) {
        qt_uart_dbg(uart1_conf.hdlr,"Unable to resolve %s\n",
							pNetwork->tlsConnectParams.pDestinationURL );
    }
    else
    {
         qt_uart_dbg(uart1_conf.hdlr,"\n%s --> %s\n addr4 : [%x]",
							pNetwork->tlsConnectParams.pDestinationURL , 
							inet_ntop(ipaddr.type, &ipaddr.a, 
							ip_str, sizeof(ip_str)),ipaddr.a.addr4);
    }

    /* ~~Create TCP socket and Connect to server address~~ */
    qt_uart_dbg(uart1_conf.hdlr,"Create TCP socket and Connect to server address");

#endif /* DNS resolver*/
	
	ges_ssl_load_cerges();

    pNetwork->tlsDataParams.eRole = QAPI_NET_SSL_CLIENT_E;

    qt_uart_dbg(uart1_conf.hdlr,"creating a new qapi_Net_SSL_Obj_New object hctxt");

    pNetwork->tlsDataParams.hCtxt = qapi_Net_SSL_Obj_New(pNetwork->tlsDataParams.eRole);

    qt_uart_dbg(uart1_conf.hdlr, "qapi_Net_SSL_Obj_New for pNetwork->tlsDataParams.hCtxt has returned [%d]",
									pNetwork->tlsDataParams.hCtxt);   

    if (QAPI_NET_SSL_INVALID_HANDLE == pNetwork->tlsDataParams.hCtxt) {
        qt_uart_dbg(uart1_conf.hdlr, "Invalid SSL handler\n");   
        return FAILURE;    
    }
	/* Load Certificates */
/*
	res = qapi_Net_SSL_Cert_Load(pNetwork->tlsDataParams.hCtxt, QAPI_NET_SSL_CA_LIST_E, TS_CLIENT_CERT_STORE_CA);
    if(res < 0 ) {
       	qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Cert_Load failed with [%d]",res);
       	return NETWORK_SSL_CERT_ERROR;
    }
*/	
	res = qapi_Net_SSL_Cert_Load(pNetwork->tlsDataParams.hCtxt, QAPI_NET_SSL_CERTIFICATE_E, TS_CLIENT_CERT_STORE_CERT);
    if(res < 0 ) {
       	qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Cert_Load failed with [%d]",res);
       	return NETWORK_SSL_CERT_ERROR;
    }
    
	/* Load Certificates */

    pNetwork->tlsDataParams.hConn = qapi_Net_SSL_Con_New(pNetwork->tlsDataParams.hCtxt, QAPI_NET_SSL_TLS_E);

    if (QAPI_NET_SSL_INVALID_HANDLE == pNetwork->tlsDataParams.hConn) {
        qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Con_New [%d]",QAPI_NET_SSL_INVALID_HANDLE);
        return NETWORK_SSL_INIT_ERROR;
    }
    qt_uart_dbg(uart1_conf.hdlr,"after qapi_Net_SSL_Con_New");
    
    /* ~~ Fill in configuration and configure SSL connection ~~ */
    if (pNetwork->tlsConnectParams.ServerVerificationFlag == IOT_TRUE) {
        qt_uart_dbg(uart1_conf.hdlr,"ServerVerificationFlag is set");
        pNetwork->tlsDataParams.sConf.verify.domain = 1;
        pNetwork->tlsDataParams.sConf.verify.send_Alert = 1;
        pNetwork->tlsDataParams.sConf.verify.time_Validity = 1;
        
        IOT_STRNCPY(pNetwork->tlsDataParams.sConf.verify.match_Name, 
						pNetwork->tlsConnectParams.pDestinationURL, 
						QAPI_NET_SSL_MAX_CERT_NAME_LEN);
    	qt_uart_dbg(uart1_conf.hdlr,"match name : [%s]",pNetwork->tlsDataParams.sConf.verify.match_Name);
		/* With verification */
	}
    else {
        pNetwork->tlsDataParams.sConf.verify.domain = 0;
        pNetwork->tlsDataParams.sConf.verify.send_Alert = 0;
        pNetwork->tlsDataParams.sConf.verify.time_Validity = 0;
        pNetwork->tlsDataParams.sConf.verify.match_Name[0] = '\0';
		/* Without verification */
    }

    pNetwork->tlsDataParams.sConf.protocol = QAPI_NET_SSL_PROTOCOL_TLS_1_2;
    pNetwork->tlsDataParams.sConf.max_Frag_Len = 16384;//4096;//16384;//4096;
    pNetwork->tlsDataParams.sConf.max_Frag_Len_Neg_Disable = 1;//0;//0;

    /* TODO: Need to check if TLSConnectParams needs to be enhanced to accept cipher suites */
	pNetwork->tlsDataParams.sConf.cipher[0] = QAPI_NET_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384; /*still need to be filled */
	pNetwork->tlsDataParams.sConf.cipher[1] = QAPI_NET_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
	pNetwork->tlsDataParams.sConf.cipher[2] = QAPI_NET_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256;
	pNetwork->tlsDataParams.sConf.cipher[3] = QAPI_NET_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
	pNetwork->tlsDataParams.sConf.cipher[4] = QAPI_NET_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
	pNetwork->tlsDataParams.sConf.cipher[5] = QAPI_NET_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
	pNetwork->tlsDataParams.sConf.cipher[6] = QAPI_NET_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
	pNetwork->tlsDataParams.sConf.cipher[7] = QAPI_NET_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
	/* Need to enhance based on the Algorithm used*/

	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.domain = [%d] , is should be 1",
								pNetwork->tlsDataParams.sConf.verify.domain);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.send_Alert = [%d] is should be 1",
								pNetwork->tlsDataParams.sConf.verify.send_Alert);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.verify.time_Validity = [%d] is shoul;d be 1",
								pNetwork->tlsDataParams.sConf.verify.time_Validity);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.max_Frag_Len = [%d]", 
								pNetwork->tlsDataParams.sConf.max_Frag_Len);
	qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sConf.max_Frag_Len_Neg_Disable = [%d]",
								pNetwork->tlsDataParams.sConf.max_Frag_Len_Neg_Disable);

    res = 0;
    qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.hConn [%d]",pNetwork->tlsDataParams.hConn);

    qt_uart_dbg(uart1_conf.hdlr,"before qapi_Net_SSL_Configure");

    res = qapi_Net_SSL_Configure(pNetwork->tlsDataParams.hConn, &(pNetwork->tlsDataParams.sConf));

    qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Configure returned [%d]",res);

    if(res < QAPI_OK) {
        pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
        qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Configure failed with NETWORK_SSL_INIT_ERROR");
        return NETWORK_SSL_INIT_ERROR;
    }

    qt_uart_dbg(uart1_conf.hdlr,"after qapi_Net_SSL_Configure");

    /* SSL configuration ends */
    /* ~~Create TCP socket and Connect to server address~~ */
    pNetwork->tlsDataParams.sock_fd = qapi_socket(family, SOCK_STREAM, 0);
    qt_uart_dbg(uart1_conf.hdlr,"qapi_socket is called [%d]",pNetwork->tlsDataParams.sock_fd);
    if (-1 == pNetwork->tlsDataParams.sock_fd)
    {
        pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
        qt_uart_dbg(uart1_conf.hdlr,"qapi_socket failed with -1");
        return NETWORK_ERR_NET_SOCKET_FAILED;
    }
    
    addr.sin_family = family;
    addr.sin_port = _htons(pNetwork->tlsConnectParams.DestinationPort);
    qt_uart_dbg(uart1_conf.hdlr,"_htons");

	qt_uart_dbg(uart1_conf.hdlr,"before assign addr.sin_addr.s_addr\n");
	addr.sin_addr.s_addr = ipaddr.a.addr4;
	qt_uart_dbg(uart1_conf.hdlr,"sin_addr.s_addr : [%x]\n",addr.sin_addr.s_addr);
//    addr.sin_addr.s_addr =  inet_addr(inet_ntop(ipaddr.type, &ipaddr.a, 
//												ip_str, sizeof(ip_str)));

    qt_uart_dbg(uart1_conf.hdlr,"calling qapi_connect"); 
    if (qapi_connect(pNetwork->tlsDataParams.sock_fd, 
					(struct sockaddr *)&addr, 
					sizeof(addr)) == -1) {
        pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
        qt_uart_dbg(uart1_conf.hdlr,"qapi_connect failed with -1"); 
        return TCP_SETUP_ERROR;
    }
    
    /* ~~set socket to blocking mode~~ */
    qt_uart_dbg(uart1_conf.hdlr,"calling qapi_setsockopt"); 
    qapi_setsockopt(pNetwork->tlsDataParams.sock_fd, SOL_SOCKET, /*SO_NBIO*/SO_BIO, NULL, 0);
    /* TODO: Need to check if this the right way to set receive timeout value*/
    qapi_setsockopt(pNetwork->tlsDataParams.sock_fd, SOL_SOCKET, SO_RCVTIMEO, 
						&pNetwork->tlsConnectParams.timeout_ms, 
						sizeof(pNetwork->tlsConnectParams.timeout_ms));
    
    /* ~~Set TCP socket to SSL conn~~ */
    qt_uart_dbg(uart1_conf.hdlr,"calling qapi_Net_SSL_FD_Set"); 
 
    res = qapi_Net_SSL_Fd_Set(pNetwork->tlsDataParams.hConn, pNetwork->tlsDataParams.sock_fd);
    if (res < 0)
    {
        qt_uart_dbg(uart1_conf.hdlr,"calling qapi_Net_SSL_FD_Set is failed with [%d]",res); 
        pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
        return NETWORK_SSL_INIT_ERROR;
    }
   qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.hConn : [%d]",
						pNetwork->tlsDataParams.hConn); 
   qt_uart_dbg(uart1_conf.hdlr,"pNetwork->tlsDataParams.sock_fd : [%d]",
						pNetwork->tlsDataParams.sock_fd); 
    /* ~~Initiate SSL handshake~~ */

	res1 = 0;
	res1 = qapi_Net_SSL_Connect(pNetwork->tlsDataParams.hConn);
    qt_uart_dbg(uart1_conf.hdlr,"SSL handshake with [%d] first connect",res1);
/*
	res1 = 0;
	res1 = qapi_Net_SSL_Connect(pNetwork->tlsDataParams.hConn);
    qt_uart_dbg(uart1_conf.hdlr,"SSL handshake with [%d] second connect",res1);
*/
	switch(res1)
	{
		case QAPI_SSL_OK_HS:
		
		/** The peer.s SSL certificate is trusted, CN matches the host name,
			time is valid */
			qt_uart_dbg(uart1_conf.hdlr,"The certificate is trusted");
            pNetwork->tlsDataParams.connectFailure = IOT_FALSE;
            result = SUCCESS;
			break;
					
		case QAPI_ERR_SSL_CERT_CN:
		
		/** The peer.s SSL certificate is trusted, CN matches the host name,
			time is expired */
			qt_uart_dbg(uart1_conf.hdlr,"ERROR: The certificate is expired");
            pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
            result = SSL_CONNECTION_ERROR;
			break;
		
		case QAPI_ERR_SSL_CERT_TIME:
		
		/** The peer.s SSL certificate is trusted, CN does NOT match the host
			name, time is valid */
			qt_uart_dbg(uart1_conf.hdlr,
						"ERROR: The certificate is trusted, but the host name is not valid");
            pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
            result = SSL_CONNECTION_ERROR;
			break;
		
		case QAPI_ERR_SSL_CERT_NONE:
		
		/** The peer.s SSL certificate is trusted, CN does NOT match host name
			, time is expired */
			qt_uart_dbg(uart1_conf.hdlr,
						"ERROR: The certificate is expired and the host name is not valid");
            pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
            result = SSL_CONNECTION_ERROR;
			break;
        default:
            pNetwork->tlsDataParams.connectFailure = IOT_TRUE;
    		qt_uart_dbg(uart1_conf.hdlr,
						"connection status  pNetwork->tlsDataParams.connectFailure = [%d]", 
						pNetwork->tlsDataParams.connectFailure);
            result = SSL_CONNECTION_ERROR;
            break;
		
	}
    return result;
}

IoT_Error_t iot_tls_read(
	Network *pNetwork, 
	unsigned char *pMsg, 
	size_t len, 
	Timer *timer, 
	size_t *read_len) 
{

    fd_set rset;
	TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
	size_t rxLen = 0;
	int ret;
    qt_uart_dbg(uart1_conf.hdlr,"inside iot_tls_read [%d] -> len",len);

    
	while (len > 0) 
    {
		/* This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read	*/
        FD_ZERO(&rset);
        FD_SET(tlsDataParams->sock_fd, &rset);
        ret = qapi_select(&rset, NULL, NULL, 500);
        if(ret > 0)
        {
            qt_uart_dbg(uart1_conf.hdlr,"sockfd in read [%d]",tlsDataParams->sock_fd);
            qt_uart_dbg(uart1_conf.hdlr,"before qapi_Net_SSL_Read Hconn [%d]", tlsDataParams->hConn);
    		ret = qapi_Net_SSL_Read(tlsDataParams->hConn, pMsg, len);
        	qt_uart_dbg(uart1_conf.hdlr,"qapi_Net_SSL_Read returned [%d]",ret);
            if (ret > 0) {
                rxLen += ret;
                pMsg += ret;
                len -= ret;
            } else if (ret != QAPI_OK) {
                qt_uart_dbg(uart1_conf.hdlr,"inside iot_tls_read returned failure NETWORK_SSL_READ_ERROR");
                return NETWORK_SSL_READ_ERROR;
            }
        }

		/* Evaluate timeout after the read to make sure read is done at least once	*/
		if (has_timer_expired(timer)) {
			qt_uart_dbg(uart1_conf.hdlr,"timer_expired");
			break;
		}
	}/* to check blocking functionality*/

	if (len == 0 || (rxLen > 0 && ret == 0)) {
		*read_len = rxLen;
		return SUCCESS;
	}

	if (rxLen == 0) {
        qt_uart_dbg(uart1_conf.hdlr,"returning NETWORK_SSL_NOTHING_TO_READ");
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
        qt_uart_dbg(uart1_conf.hdlr,"returning NETWORK_SSL_READ_TIMEOUT_ERROR");
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

IoT_Error_t iot_tls_disconnect(Network *pNetwork)
{
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    qt_uart_dbg(uart1_conf.hdlr,"inside iot_tls_disconnect");
    
    if (tlsDataParams->hConn != QAPI_NET_SSL_INVALID_HANDLE)
    {
        qapi_Net_SSL_Shutdown(tlsDataParams->hConn);
        tlsDataParams->hConn = QAPI_NET_SSL_INVALID_HANDLE;
    }
    if (tlsDataParams->sock_fd != -1)
    {
        qapi_socketclose(tlsDataParams->sock_fd);
        tlsDataParams->sock_fd = -1;
    }
    qt_uart_dbg(uart1_conf.hdlr,"exiting iot_tls_disconnect");
    return SUCCESS;
}

IoT_Error_t iot_tls_destroy(Network *pNetwork)
{
    TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
    
    if (tlsDataParams->hCtxt != QAPI_NET_SSL_INVALID_HANDLE)
    {
        qapi_Net_SSL_Obj_Free(tlsDataParams->hCtxt);
        tlsDataParams->hCtxt = QAPI_NET_SSL_INVALID_HANDLE;
    }
}

IoT_Error_t iot_tls_init(Network *pNetwork, char *pRootCALocation, 
						char *pDeviceCertLocation, char *pDevicePrivateKeyLocation, 
						char *pDestinationURL, uint16_t DestinationPort, 
						uint32_t timeout_ms, bool ServerVerificationFlag)
{
    qt_uart_dbg(uart1_conf.hdlr,"inside iot tls init");
	if (NULL == pNetwork)
		return NULL_VALUE_ERROR;
    
	pNetwork->tlsConnectParams.DestinationPort = DestinationPort;
	pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
	pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
	pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
	pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
	pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
	pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
    
    qt_uart_dbg(uart1_conf.hdlr,"DestinationPort [%d]",
								pNetwork->tlsConnectParams.DestinationPort);
    qt_uart_dbg(uart1_conf.hdlr,"pDestinationURL [%s]",
								pNetwork->tlsConnectParams.pDestinationURL);
    qt_uart_dbg(uart1_conf.hdlr,"pDeviceCertLocation [%s]",
								pNetwork->tlsConnectParams.pDeviceCertLocation);
    qt_uart_dbg(uart1_conf.hdlr,"pDevicePrivateKeyLocation [%s]",
								pNetwork->tlsConnectParams.pDevicePrivateKeyLocation);
    qt_uart_dbg(uart1_conf.hdlr,"pRootCALocation [%s]",
								pNetwork->tlsConnectParams.pRootCALocation);
    qt_uart_dbg(uart1_conf.hdlr,"timeout_ms [%d]",
								pNetwork->tlsConnectParams.timeout_ms);
    qt_uart_dbg(uart1_conf.hdlr,"ServerVerificationFlag [%d]",
								pNetwork->tlsConnectParams.ServerVerificationFlag);
    
	pNetwork->connect = iot_tls_connect;
	pNetwork->read = iot_tls_read;
	pNetwork->write = iot_tls_write;
	pNetwork->disconnect = iot_tls_disconnect;
	pNetwork->isConnected = iot_tls_is_connected;
	pNetwork->destroy = iot_tls_destroy;
    
    qt_uart_dbg(uart1_conf.hdlr,"initialization done");

	return SUCCESS;
}


#ifdef __cplusplus
}
#endif
