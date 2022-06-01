/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_credential_service.h"
#include <pthread.h>
#include <unistd.h>
#include "dlp_credential_service_defines.h"
#include "dlp_permission_log.h"
#include "securec.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DlpCredentialService"
#endif

static uint64_t g_requestId = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct PackPolicyCallbackTaskPara {
    DLP_PackPolicyCallback callback;
    uint64_t requestId;
    int errorCode;
    DLP_PackPolicyParams* params;
} PackPolicyCallbackTaskPara;

typedef struct RestorePolicyCallbackTaskPara {
    DLP_RestorePolicyCallback callback;
    uint64_t requestId;
    int errorCode;
    DLP_EncPolicyData* params;
} RestorePolicyCallbackTaskPara;

static void FreePackPolicyCallbackTaskPara(PackPolicyCallbackTaskPara* taskParams)
{
    if (taskParams != NULL) {
        free(taskParams->params->featureName);
        taskParams->params->featureName = NULL;
        free(taskParams->params->data);
        taskParams->params->data = NULL;
        free(taskParams->params);
        taskParams->params = NULL;
        free(taskParams);
    }
}

static void FreeRestorePolicyCallbackTaskPara(RestorePolicyCallbackTaskPara* taskParams)
{
    if (taskParams != NULL) {
        free(taskParams->params->featureName);
        taskParams->params->featureName = NULL;
        free(taskParams->params->data);
        taskParams->params->data = NULL;
        free(taskParams->params);
        taskParams->params = NULL;
        free(taskParams);
    }
}

static void* PackPolicyCallbackTask(void* inputTaskParams)
{
    DLP_LOG_DEBUG("Called");
    if (inputTaskParams == NULL) {
        DLP_LOG_ERROR("InputTaskParams is null");
        return NULL;
    }
    PackPolicyCallbackTaskPara* taskParams = (PackPolicyCallbackTaskPara*)inputTaskParams;
    if (taskParams->callback == NULL) {
        DLP_LOG_ERROR("Callback is null");
        FreePackPolicyCallbackTaskPara(taskParams);
        return NULL;
    }

    DLP_EncPolicyData outParams = {
        .featureName = taskParams->params->featureName,
        .data = taskParams->params->data,
        .dataLen = taskParams->params->dataLen,
    };

    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    FreePackPolicyCallbackTaskPara(taskParams);
    return NULL;
}

static void* RestorePolicyCallbackTask(void* inputTaskParams)
{
    DLP_LOG_DEBUG("Called");
    if (inputTaskParams == NULL) {
        DLP_LOG_ERROR("InputTaskParams is null");
        return NULL;
    }
    RestorePolicyCallbackTaskPara* taskParams = (RestorePolicyCallbackTaskPara*)inputTaskParams;
    if (taskParams->callback == NULL) {
        DLP_LOG_ERROR("Callback is null");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return NULL;
    }

    DLP_RestorePolicyData outParams = {
        .data = taskParams->params->data,
        .dataLen = taskParams->params->dataLen,
    };

    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    FreeRestorePolicyCallbackTaskPara(taskParams);
    return NULL;
}

/**
 * 发送端请求打包策略
 *
 * @param [in]userId 本地用户id
 * @param [in]params 请求打包凭据的参数，详见DLP_PackParams结构体定义
 * @param [in]callback 发送端打包策略的回调，打包策略的结果由此回调返回给调用方
 * @param [out]requestId 调用标识，由DLP凭据管理生成唯一的标识，返回给调用方
 * @return
 */
int DLP_PackPolicy(
    uint32_t userId, const DLP_PackPolicyParams* params, DLP_PackPolicyCallback callback, uint64_t* requestId)
{
    DLP_LOG_DEBUG("Called");
    if (params == NULL || params->data == NULL || params->featureName == NULL || callback == NULL ||
        requestId == NULL) {
        DLP_LOG_ERROR("Callback or params is null");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    int id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    PackPolicyCallbackTaskPara* taskParams = (PackPolicyCallbackTaskPara*)malloc(sizeof(PackPolicyCallbackTaskPara));
    if (taskParams == NULL) {
        DLP_LOG_ERROR("New memory fail");
        return -1;
    }
    taskParams->callback = callback;
    taskParams->requestId = *requestId;
    taskParams->errorCode = 0;
    taskParams->params = (DLP_PackPolicyParams*)malloc(sizeof(DLP_PackPolicyParams));
    if (taskParams->params == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->featureName = (char*)strdup(params->featureName);
    if (taskParams->params->featureName == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->data = (uint8_t*)malloc(params->dataLen);
    if (taskParams->params->data == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    if (memcpy_s(taskParams->params->data, params->dataLen, params->data, params->dataLen) != EOK) {
        DLP_LOG_ERROR("Memcpy_s fail");
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->dataLen = params->dataLen;
    taskParams->params->accountType = params->accountType;

    pthread_t t;
    pthread_create(&t, NULL, PackPolicyCallbackTask, taskParams);
    pthread_detach(t);
    return 0;
}

/**
 * 接收端请求解析策略
 *
 * @param [in]userId 本地用户id
 * @param [in]params 请求解析策略的参数，详见DLP_OutputPackParams结构体定义
 * @param [in]callback 接收端解析策略的回调，解析策略的结果由此回调返回给调用方
 * @param [out]requestId 调用标识，由DLP凭据管理生成唯一的标识，返回给调用方
 * @return
 */
int DLP_RestorePolicy(
    uint32_t userId, const DLP_EncPolicyData* params, DLP_RestorePolicyCallback callback, uint64_t* requestId)
{
    DLP_LOG_DEBUG("Called");
    if (params == NULL || params->data == NULL || params->featureName == NULL || callback == NULL ||
        requestId == NULL) {
        DLP_LOG_ERROR("Callback or params is null");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    int id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    RestorePolicyCallbackTaskPara* taskParams =
        (RestorePolicyCallbackTaskPara*)malloc(sizeof(RestorePolicyCallbackTaskPara));
    if (taskParams == NULL) {
        DLP_LOG_ERROR("New memory fail");
        return -1;
    }
    taskParams->callback = callback;
    taskParams->requestId = *requestId;
    taskParams->errorCode = 0;
    taskParams->params = (DLP_EncPolicyData*)malloc(sizeof(DLP_EncPolicyData));
    if (taskParams->params == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->featureName = (char*)strdup(params->featureName);
    if (taskParams->params->featureName == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->data = (uint8_t*)malloc(params->dataLen);
    if (taskParams->params->data == NULL) {
        DLP_LOG_ERROR("New memory fail");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    if (memcpy_s(taskParams->params->data, params->dataLen, params->data, params->dataLen) != EOK) {
        DLP_LOG_ERROR("Memcpy_s fail");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    taskParams->params->dataLen = params->dataLen;

    pthread_t t;
    pthread_create(&t, NULL, RestorePolicyCallbackTask, taskParams);
    pthread_detach(t);
    return 0;
}
