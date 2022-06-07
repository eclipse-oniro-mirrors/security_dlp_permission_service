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
typedef void (*DLP_PackPolicyCallback)(uint64_t requestId, int errorCode, DLP_EncPolicyData* outParams);
typedef void (*DLP_RestorePolicyCallback)(uint64_t requestId, int errorCode, DLP_RestorePolicyData* outParams);

int DLP_PackPolicy(
    uint32_t userId, const DLP_PackPolicyParams* packParams, DLP_PackPolicyCallback callback, uint64_t* requestId);
int DLP_RestorePolicy(
    uint32_t userId, const DLP_EncPolicyData* encData, DLP_RestorePolicyCallback callback, uint64_t* requestId);
#ifdef __cplusplus
}
#endif

#endif