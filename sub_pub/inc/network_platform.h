
/**
 * @file network_platform.h
 * @brief Internal data structure to hold platform specific network handles
 *
 * Defines Data Structure that hold platform specific handles of various objects for 
 * each connection
 */

#ifndef _IOT_AWS_QAPI_NETWORK_H_

#define _IOT_AWS_QAPI_NETWORK_H_

#include "qapi_ssl.h"

/**
 * @brief TLS Connection Params handles
 *
 * Defines structure type containing various handle of a connection
 */
struct _tlsDataParams
{
    qapi_Net_SSL_Obj_Hdl_t  hCtxt;
    qapi_Net_SSL_Con_Hdl_t  hConn;
    qapi_Net_SSL_Config_t   sConf;
    qapi_Net_SSL_Role_t     eRole;
    int sock_fd;
    bool connectFailure;    
};

typedef struct _tlsDataParams TLSDataParams;

#endif //_IOT_AWS_QAPI_NETWORK_H_

