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
    DLP_PackPolicyParams* packParams;
} PackPolicyCallbackTaskPara;

typedef struct RestorePolicyCallbackTaskPara {
    DLP_RestorePolicyCallback callback;
    uint64_t requestId;
    int errorCode;
    DLP_EncPolicyData* encData;
} RestorePolicyCallbackTaskPara;

static void FreePackPolicyCallbackTaskPara(PackPolicyCallbackTaskPara* taskParams)
{
    if (taskParams != NULL) {
        free(taskParams->packParams->featureName);
        taskParams->packParams->featureName = NULL;
        free(taskParams->packParams->data);
        taskParams->packParams->data = NULL;
        free(taskParams->packParams);
        taskParams->packParams = NULL;
        free(taskParams);
    }
}

static void FreeRestorePolicyCallbackTaskPara(RestorePolicyCallbackTaskPara* taskParams)
{
    if (taskParams != NULL) {
        free(taskParams->encData->featureName);
        taskParams->encData->featureName = NULL;
        free(taskParams->encData->data);
        taskParams->encData->data = NULL;
        free(taskParams->encData);
        taskParams->encData = NULL;
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
        .featureName = taskParams->packParams->featureName,
        .data = taskParams->packParams->data,
        .dataLen = taskParams->packParams->dataLen,
    };

    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    DLP_LOG_INFO("End thread, requestId: %{public}llu", (unsigned long long)taskParams->requestId);
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
        .data = taskParams->encData->data,
        .dataLen = taskParams->encData->dataLen,
    };

    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    DLP_LOG_INFO("End thread, requestId: %{public}llu", (unsigned long long)taskParams->requestId);
    FreeRestorePolicyCallbackTaskPara(taskParams);
    return NULL;
}

static PackPolicyCallbackTaskPara* TransPackPolicyParams(
    const DLP_PackPolicyParams* params, DLP_PackPolicyCallback callback, uint64_t requestId)
{
    PackPolicyCallbackTaskPara* taskParams = (PackPolicyCallbackTaskPara*)malloc(sizeof(PackPolicyCallbackTaskPara));
    if (taskParams == NULL) {
        goto err;
    }
    taskParams->callback = callback;
    taskParams->requestId = requestId;
    taskParams->errorCode = 0;
    taskParams->packParams = (DLP_PackPolicyParams*)malloc(sizeof(DLP_PackPolicyParams));
    if (taskParams->packParams == NULL) {
        goto err;
    }
    taskParams->packParams->featureName = (char*)strdup(params->featureName);
    if (taskParams->packParams->featureName == NULL) {
        goto err;
    }
    taskParams->packParams->data = (uint8_t*)malloc(params->dataLen);
    if (taskParams->packParams->data == NULL) {
        goto err;
    }
    if (memcpy_s(taskParams->packParams->data, params->dataLen, params->data, params->dataLen) != EOK) {
        goto err;
    }
    taskParams->packParams->dataLen = params->dataLen;
    taskParams->packParams->accountType = params->accountType;
    return taskParams;
err:
    DLP_LOG_ERROR("Memory operate fail");
    FreePackPolicyCallbackTaskPara(taskParams);
    return NULL;
}

int DLP_PackPolicy(
    uint32_t userId, const DLP_PackPolicyParams* packParams, DLP_PackPolicyCallback callback, uint64_t* requestId)
{
    (void)userId;
    DLP_LOG_DEBUG("Called");
    if (packParams == NULL || packParams->data == NULL || packParams->featureName == NULL || callback == NULL ||
        requestId == NULL) {
        DLP_LOG_ERROR("Callback or params is null");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    uint64_t id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    PackPolicyCallbackTaskPara* taskParams = TransPackPolicyParams(packParams, callback, *requestId);
    if (taskParams == NULL) {
        return -1;
    }

    pthread_t t;
    int32_t ret = pthread_create(&t, NULL, PackPolicyCallbackTask, taskParams);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_create failed %d\n", ret);
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    ret = pthread_detach(t);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_detach failed %d\n", ret);
        FreePackPolicyCallbackTaskPara(taskParams);
        return -1;
    }
    DLP_LOG_INFO("Start new thread, requestId: %{public}llu", (unsigned long long)*requestId);
    return 0;
}

static RestorePolicyCallbackTaskPara* TransEncPolicyData(
    const DLP_EncPolicyData* params, DLP_RestorePolicyCallback callback, uint64_t requestId)
{
    RestorePolicyCallbackTaskPara* taskParams =
        (RestorePolicyCallbackTaskPara*)malloc(sizeof(RestorePolicyCallbackTaskPara));
    if (taskParams == NULL) {
        goto err;
    }
    taskParams->callback = callback;
    taskParams->requestId = requestId;
    taskParams->errorCode = 0;
    taskParams->encData = (DLP_EncPolicyData*)malloc(sizeof(DLP_EncPolicyData));
    if (taskParams->encData == NULL) {
        goto err;
    }
    taskParams->encData->featureName = (char*)strdup(params->featureName);
    if (taskParams->encData->featureName == NULL) {
        goto err;
    }
    taskParams->encData->data = (uint8_t*)malloc(params->dataLen);
    if (taskParams->encData->data == NULL) {
        goto err;
    }
    if (memcpy_s(taskParams->encData->data, params->dataLen, params->data, params->dataLen) != EOK) {
        goto err;
    }
    taskParams->encData->dataLen = params->dataLen;
    return taskParams;
err:
    DLP_LOG_ERROR("Memory operate fail");
    FreeRestorePolicyCallbackTaskPara(taskParams);
    return NULL;
}

int DLP_RestorePolicy(
    uint32_t userId, const DLP_EncPolicyData* encData, DLP_RestorePolicyCallback callback, uint64_t* requestId)
{
    (void)userId;
    DLP_LOG_DEBUG("Called");
    if (encData == NULL || encData->data == NULL || encData->featureName == NULL || callback == NULL ||
        requestId == NULL) {
        DLP_LOG_ERROR("Callback or params is null");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    uint64_t id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    RestorePolicyCallbackTaskPara* taskParams = TransEncPolicyData(encData, callback, *requestId);
    if (taskParams == NULL) {
        return -1;
    }

    pthread_t t;
    int32_t ret = pthread_create(&t, NULL, RestorePolicyCallbackTask, taskParams);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_create failed %d\n", ret);
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    ret = pthread_detach(t);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_detach failed %d\n", ret);
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return -1;
    }
    DLP_LOG_INFO("Start new thread, requestId: %{public}llu", (unsigned long long)*requestId);
    return 0;
}
