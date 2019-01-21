/*
 * Copyright (c) 2017-2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 */
// Copyright (c) 2018 Qualcomm Technologies, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without modification, are permitted (subject to the limitations in the disclaimer below) 
// provided that the following conditions are met:
// Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice, 
// this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
// Neither the name of Qualcomm Technologies, Inc. nor the names of its contributors may be used to endorse or promote products derived 
// from this software without specific prior written permission.
// NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE. 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
// BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/**
 * @file timer.c
 * @brief Linux implementation of the timer interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "txm_module.h"

#include <stddef.h>
#include "qapi_diag.h"
#include "qapi_timer.h"
#include "timer_platform.h"

//porting on quectel...may not be needed
//#include "netutils.h"
extern void app_print(qapi_time_get_t *time_info);

void app_get_time(qapi_time_unit_type type, qapi_time_get_t *time_info)
{
	memset(time_info, 0, sizeof(qapi_time_get_t));
    qapi_time_get(type, time_info); 
    /*if(type == QAPI_TIME_MSECS)
        app_print(time_info);*/
}

bool has_timer_expired(Timer *timer) {
    qapi_time_get_t time_info;
    unsigned long now;

    app_get_time(QAPI_TIME_MSECS, &time_info);
    
    now = time_info.time_msecs;

    if (now >= timer->end_time)
    {
        return 1;
    }
    else
    {
        return 0;
    }

}

void countdown_ms(Timer *timer, uint32_t timeout) 
{
    qapi_time_get_t time_info;
    unsigned long now;

    app_get_time(QAPI_TIME_MSECS, &time_info);
    
    now = time_info.time_msecs;
    
    timer->end_time = now + timeout;
  
}

uint32_t left_ms(Timer *timer) 
{
    qapi_time_get_t time_info;
    unsigned long now;

    app_get_time(QAPI_TIME_MSECS, &time_info);
    
    now = time_info.time_msecs;

    
    return (uint32_t)(timer->end_time - now);    
}

void countdown_sec(Timer *timer, uint32_t timeout)
{
    qapi_time_get_t time_info;
    unsigned long now;

    app_get_time(QAPI_TIME_MSECS, &time_info);
    
    now = time_info.time_msecs;

    
    timer->end_time = now + (timeout * 1000);

}

void init_timer(Timer *timer) {

    timer->end_time = 0;
}

#ifdef __cplusplus
}
#endif
