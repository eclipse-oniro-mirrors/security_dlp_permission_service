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

#ifndef DLP_CREDENTIAL_SERVICE_H
#define DLP_CREDENTIAL_SERVICE_H

#include <stdint.h>
#include "dlp_credential_service_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 发送端打包策略的回调
 */
typedef void (*DLP_PackPolicyCallback)(uint64_t requestId, int errorCode, DLP_EncPolicyData* outParams);
/**
 * 接收端解析策略的回调
 */
typedef void (*DLP_RestorePolicyCallback)(uint64_t requestId, int errorCode, DLP_RestorePolicyData* outParams);

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
    uint32_t userId, const DLP_PackPolicyParams* params, DLP_PackPolicyCallback callback, uint64_t* requestId);

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
    uint32_t userId, const DLP_EncPolicyData* params, DLP_RestorePolicyCallback callback, uint64_t* requestId);

#ifdef __cplusplus
}
#endif

#endif