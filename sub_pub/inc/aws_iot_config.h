#ifndef SRC_SHADOW_IOT_SHADOW_CONFIG_H_
#define SRC_SHADOW_IOT_SHADOW_CONFIG_H_

//important headers and macros from quart
#include "qapi_uart.h"

/* buffer size Must be @ge 4 and a multiple of 4 */
#define APP_UART_BUFF_SIZE	128

#define APP_UART_1_PORT		QAPI_UART_PORT_001_E
#define APP_UART_2_PORT	 	QAPI_UART_PORT_002_E
#define APP_UART_3_PORT	 	QAPI_UART_PORT_003_E

#define QT_UART_ENABLE_1ST
#define QT_UART_ENABLE_2ND
#define QT_UART_ENABLE_3RD

#if 1
#define AWS_IOT_MQTT_HOST              "a11hq9a0r6cqjs-ats.iot.eu-west-1.amazonaws.com" 
/*< Customer specific MQTT HOST. The same will be used for Thing Shadow*/       
#define AWS_IOT_MQTT_PORT              8883 ///< default port for MQTT/S        
//#define AWS_IOT_MQTT_CLIENT_ID         "Cloud_MDM_QUECTL" ///< MQTT client ID should be unique for every device
//#define AWS_IOT_MY_THING_NAME          "Cloud_MDM" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_MQTT_CLIENT_ID         "QCA4020_MUSIC_FTV_BG96" ///< MQTT client ID should be unique for every device
#define AWS_IOT_MY_THING_NAME          "QCA4020_MUSIC_FTV" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_ROOT_CA_FILENAME       "root-CA.crt" ///< Root CA file name     
#define AWS_IOT_CERTIFICATE_FILENAME   "QCA4020_MUSIC_FTV.cert.pem" ///< device signed certificate file name
#define AWS_IOT_PRIVATE_KEY_FILENAME   "QCA4020_MUSIC_FTV.private.key" ///< Device private key filename
#define APN_CONFIG "APN_CONFIG.txt" // APN Config filename
#endif

#if 0
#define AWS_IOT_MQTT_HOST              "asofavkjfjmc-ats.iot.us-east-1.amazonaws.com" ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
#define AWS_IOT_MQTT_PORT              8883 ///< default port for MQTT/S         
#define AWS_IOT_MQTT_CLIENT_ID         "Cellular" ///< MQTT client ID should be unique for every device
#define AWS_IOT_MY_THING_NAME          "Cellular" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_ROOT_CA_FILENAME       "root-CA.crt" ///< Root CA file name      
#define AWS_IOT_CERTIFICATE_FILENAME   "7273e24024-certificate.pem.crt" ///< device signed certificate file name
#define AWS_IOT_PRIVATE_KEY_FILENAME   "7273e24024-private.pem.key" ///< Device private key filename
#endif

#if 0
#define AWS_IOT_MQTT_HOST              "asofavkjfjmc-ats.iot.us-east-1.amazonaws.com" ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
#define AWS_IOT_MQTT_PORT              8883 ///< default port for MQTT/S
#define AWS_IOT_MQTT_CLIENT_ID         "Cloud_MDM_QUECTL" ///< MQTT client ID should be unique for every device
#define AWS_IOT_MY_THING_NAME          "Cloud_MDM" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_ROOT_CA_FILENAME       "rootCA.crt" ///< Root CA file name
#define AWS_IOT_CERTIFICATE_FILENAME   "49bec62644-certificate.pem.crt" ///< device signed certificate file name
#define AWS_IOT_PRIVATE_KEY_FILENAME   "49bec62644-private.pem.key" ///< Device private key filename
#endif
// MQTT PubSub
#define AWS_IOT_MQTT_TX_BUF_LEN 512 ///< Any time a message is sent out through the MQTT layer. The message is copied into this buffer anytime a publish is done. This will also be used in the case of Thing Shadow
#define AWS_IOT_MQTT_RX_BUF_LEN 512 ///< Any message that comes into the device should be less than this buffer size. If a received message is bigger than this buffer size the message will be dropped.
#define AWS_IOT_MQTT_NUM_SUBSCRIBE_HANDLERS 5 ///< Maximum number of topic filters the MQTT client can handle at any given time. This should be increased appropriately when using Thing Shadow

// Thing Shadow specific configs
#define SHADOW_MAX_SIZE_OF_RX_BUFFER (AWS_IOT_MQTT_RX_BUF_LEN+1) ///< Maximum size of the SHADOW buffer to store the received Shadow message, including terminating NULL byte.
#define MAX_SIZE_OF_UNIQUE_CLIENT_ID_BYTES 80  ///< Maximum size of the Unique Client Id. For More info on the Client Id refer \ref response "Acknowledgments"
#define MAX_SIZE_CLIENT_ID_WITH_SEQUENCE MAX_SIZE_OF_UNIQUE_CLIENT_ID_BYTES + 10 ///< This is size of the extra sequence number that will be appended to the Unique client Id
#define MAX_SIZE_CLIENT_TOKEN_CLIENT_SEQUENCE MAX_SIZE_CLIENT_ID_WITH_SEQUENCE + 20 ///< This is size of the the total clientToken key and value pair in the JSON
#define MAX_ACKS_TO_COMEIN_AT_ANY_GIVEN_TIME 10 ///< At Any given time we will wait for this many responses. This will correlate to the rate at which the shadow actions are requested
#define MAX_THINGNAME_HANDLED_AT_ANY_GIVEN_TIME 10 ///< We could perform shadow action on any thing Name and this is maximum Thing Names we can act on at any given time
#define MAX_JSON_TOKEN_EXPECTED 120 ///< These are the max tokens that is expected to be in the Shadow JSON document. Include the metadata that gets published
#define MAX_SHADOW_TOPIC_LENGTH_WITHOUT_THINGNAME 60 ///< All shadow actions have to be published or subscribed to a topic which is of the format $aws/things/{thingName}/shadow/update/accepted. This refers to the size of the topic without the Thing Name
#define MAX_SIZE_OF_THING_NAME 20 ///< The Thing Name should not be bigger than this value. Modify this if the Thing Name needs to be bigger
#define MAX_SHADOW_TOPIC_LENGTH_BYTES MAX_SHADOW_TOPIC_LENGTH_WITHOUT_THINGNAME + MAX_SIZE_OF_THING_NAME ///< This size includes the length of topic with Thing Name

// Auto Reconnect specific config
#define AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL 1000 ///< Minimum time before the First reconnect attempt is made as part of the exponential back-off algorithm
#define AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL 128000 ///< Maximum time interval after which exponential back-off will stop attempting to reconnect.

#define DISABLE_METRICS false ///< Disable the collection of metrics by setting this to true

#endif /* SRC_SHADOW_IOT_SHADOW_CONFIG_H_ */