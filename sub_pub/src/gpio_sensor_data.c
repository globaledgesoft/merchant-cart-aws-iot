/******************************************************************************
*@file    example_task.c
*@brief   example of new task creation
*
*  ---------------------------------------------------------------------------
*
*  Copyright (c) 2018 Quectel Technologies, Inc.
*  All Rights Reserved.
*  Confidential and Proprietary - Quectel Technologies, Inc.
*  ---------------------------------------------------------------------------
*******************************************************************************/
//#if defined(__EXAMPLE_TASK_CREATE__)
#include "txm_module.h"
#include "qapi_diag.h"
#include "qapi_timer.h"
#include "qapi_uart.h"
#include "quectel_utils.h"
#include "quectel_uart_apis.h"
#include "queue_config.h"
#include "qapi_gpioint.h"
#include "quectel_gpio.h"
/**************************************************************************
*                                 DEFINE
***************************************************************************/
#define QT_SUB1_THREAD_PRIORITY   	180
#define QT_SUB1_THREAD_STACK_SIZE 	(1024 * 16)

#define QT_TIMER_THREAD_PRIORITY   	170
#define QT_TIMER_THREAD_STACK_SIZE 	(1024 * 2)


/**************************************************************************
*                                 GLOBAL
***************************************************************************/
/* uart rx tx buffer */
static char rx_buff[1024];
static char tx_buff[1024];

static GPIO_MAP_TBL gpio_map_tbl[PIN_E_GPIO_MAX] = {
/* PIN NUM,     PIN NAME,    GPIO ID  GPIO FUNC */
	{  4, 		"GPIO01",  		23, 	 0},
	{  5, 		"GPIO02",  		20, 	 0},
	{  6, 		"GPIO03",  		21, 	 0},
	{  7, 		"GPIO04",  		22, 	 0},
	{ 19, 		"GPIO06",  		10, 	 0},
	{ 22, 		"GPIO07",  		 9, 	 0},
	{ 23, 		"GPIO08",  	 	 8, 	 0},
	{ 26, 		"GPIO09",  		15, 	 0},
    { 18, 		"GPIO05",  		11, 	 0},
	{ 27, 		"GPIO10",  		12, 	 0},
	{ 28, 		"GPIO11",  		13, 	 0},
	{ 40, 		"GPIO19",  		19, 	 0},
	{ 41, 		"GPIO20",  		18, 	 0},
	{ 64, 		"GPIO21",  		07, 	 0},
};
static qapi_Instance_Handle_t InventoryGPIOUpdateIntHdlr;
static int inventory_update = 0;
static unsigned int num_sensors = 5;

/* uart config para*/
extern QT_UART_CONF_PARA uart1_conf ;
/*
{
	NULL,
	QT_UART_PORT_02,
	tx_buff,
	sizeof(tx_buff),
	rx_buff,
	sizeof(rx_buff),
	115200
};*/

/* conter used to count the total run times for main task */
static unsigned long main_thread_run_couter = 0;
/* conter used to count the total run times for sub1 task */
static unsigned long sub1_thread_run_couter = 0;

/* thread handle */
static TX_THREAD* qt_sub1_thread_handle; 
static unsigned char qt_sub1_thread_stack[QT_SUB1_THREAD_STACK_SIZE];

static TX_THREAD* qt_timer_thread_handle; 
static unsigned char qt_timer_thread_stack[QT_TIMER_THREAD_STACK_SIZE];


/* TX QUEUE handle */
 TX_QUEUE tx_queue_handle;

extern void app_get_time(qapi_time_unit_type type, qapi_time_get_t *time_info);

/* TX QUEUE buffer */
static TASK_COMM task_comm[QUEUE_SIZE];

void app_print(qapi_time_get_t *time_info)
{
	qt_uart_dbg(uart1_conf.hdlr, "app print time %lld ms", time_info->time_msecs);
}

/**************************************************************************
*                           FUNCTION DECLARATION
***************************************************************************/
//void quectel_sub1_task_entry(ULONG para);
extern int quectel_aws_task_entry(void);

TASK_COMM qt_timer_task_comm;


int igaws_timer_callback(void)
{
	while(1)
	{
		qapi_Timer_Sleep(300, QAPI_TIMER_UNIT_SEC, true);
		qt_timer_task_comm.type = AWS_TIMER;
		tx_queue_send(&tx_queue_handle, &qt_timer_task_comm, 0);
	}
}


void create_timer_thread()
{
	int ret = -1;
	/* create a new task */
	if(TX_SUCCESS != txm_module_object_allocate((VOID *)&qt_timer_thread_handle, sizeof(TX_THREAD))) 
	{
		qt_uart_dbg(uart1_conf.hdlr,"[task_create] timer thread txm_module_object_allocate failed ~");
		IOT_INFO("[task_create] txm_module_object_allocate failed ~");
		return;
	}

	/* create a new task : sub1 */
	ret = tx_thread_create(qt_timer_thread_handle,
						   "AWS yield timer Task Thread",
						   igaws_timer_callback,
						   NULL,
						   qt_timer_thread_stack,
						   QT_TIMER_THREAD_STACK_SIZE,
						   QT_TIMER_THREAD_PRIORITY,
						   QT_TIMER_THREAD_PRIORITY,
						   TX_NO_TIME_SLICE,
						   TX_AUTO_START
						   );
	      
	if(ret != TX_SUCCESS)
	{
		qt_uart_dbg(uart1_conf.hdlr,"[task_create] : Timer Thread creation failed");
		return;
	}


	qt_uart_dbg(uart1_conf.hdlr,"[task_create] : Timer Thread creation success");


}

/**************************************************************************
*                                 FUNCTION
***************************************************************************/
void InventoryUpdateCallback(qapi_GPIOINT_Callback_Data_t data)
{	
	inventory_update++;
}

/*
@func
  quectel_task_entry
@brief
  Entry function for task. 
*/
/*=========================================================================*/
int quectel_task_entry(void)
{
	int ret = -1;
	UINT status = 0;
    uint32 message_size;
	TASK_COMM qt_main_task_comm;
	int gpio = 0;
	qapi_Timer_Sleep(1, QAPI_TIMER_UNIT_SEC, true);

	/* uart 1 init */
	uart_init(&uart1_conf);

	/* start uart 1 receive */
	uart_recv(&uart1_conf);

	/* prompt task running */
	qt_uart_dbg(uart1_conf.hdlr,"[task_create] start task ~");
#if 0
	while(1)
	{
	    qapi_time_get_t time_info, ms_time_info;
		qapi_Timer_Sleep(1, QAPI_TIMER_UNIT_SEC, true);
		app_get_time(QAPI_TIME_JULIAN, &time_info);
		app_get_time(QAPI_TIME_MSECS, &ms_time_info);
		qt_uart_dbg(uart1_conf.hdlr, "current time %lld ms", ms_time_info.time_msecs);
		qt_uart_dbg(uart1_conf.hdlr, "current year %04d", time_info.time_julian.year);
		if(time_info.time_julian.year != 1980)
			break;
	}

#endif

	/* create a new task */
	if(TX_SUCCESS != txm_module_object_allocate((VOID *)&qt_sub1_thread_handle, sizeof(TX_THREAD))) 
	{
		qt_uart_dbg(uart1_conf.hdlr,"[task_create] txm_module_object_allocate failed ~");
		IOT_INFO("[task_create] txm_module_object_allocate failed ~");
		return - 1;
	}

	/* create a new task : sub1 */
	ret = tx_thread_create(qt_sub1_thread_handle,
						   "AWS Main Task Thread",
						   quectel_aws_task_entry,
						   NULL,
						   qt_sub1_thread_stack,
						   QT_SUB1_THREAD_STACK_SIZE,
						   QT_SUB1_THREAD_PRIORITY,
						   QT_SUB1_THREAD_PRIORITY,
						   TX_NO_TIME_SLICE,
						   TX_AUTO_START
						   );
	      
	if(ret != TX_SUCCESS)
	{
		qt_uart_dbg(uart1_conf.hdlr,"[task_create] : Thread creation failed");
		IOT_INFO("[task_create] : Thread creation failed");
	}

	message_size = sizeof(TASK_COMM)/sizeof(uint32);

	/* create a new queue : q_task_comm */
	status = tx_queue_create(&tx_queue_handle,
							 "q_task_comm",
							 message_size,
							 task_comm,
							 QUEUE_SIZE * sizeof(TASK_COMM)
							 );
	if (TX_SUCCESS != status)
	{
		qt_uart_dbg(uart1_conf.hdlr, "tx_queue_create failed with status %d", status);
	}
	else
	{
		qt_uart_dbg(uart1_conf.hdlr, "tx_queue_create ok with status %d", status);
	}

	while(gpio < num_sensors) {
		if (qapi_GPIOINT_Register_Interrupt(&InventoryGPIOUpdateIntHdlr,
								gpio_map_tbl[gpio].gpio_id,
								InventoryUpdateCallback,
								NULL,
								QAPI_GPIOINT_TRIGGER_EDGE_FALLING_E,
								QAPI_GPIOINT_PRIO_MEDIUM_E,
								false)!= QAPI_OK) {
			qt_uart_dbg(uart1_conf.hdlr,"GPIO Interrupt Registeration failed\n");
			return -1;
		}
		gpio++;
	}
	
	while (1)
	{
        if(inventory_update > 0) {
		    qt_main_task_comm.type = AWS_PUBLISH;
		    qt_main_task_comm.data = inventory_update;
		    /* send data to sub1 task by queue */
		    status = tx_queue_send(&tx_queue_handle, &qt_main_task_comm, 0);
		    if (TX_SUCCESS != status)
		    {
			    qt_uart_dbg(uart1_conf.hdlr, "[task_create] tx_queue_send failed with status %d", status);
            }   
		    else
		    {
                --inventory_update;
		        //qt_uart_dbg(uart1_conf.hdlr, "tx_queue_send ok with status %d", status);
		    }
        }   
		/* sleep 2 seconds */
		qapi_Timer_Sleep(1, QAPI_TIMER_UNIT_SEC, true);
	}

	return 0;
}

//#endif /*__EXAMPLE_TASK_CREATE__*/


