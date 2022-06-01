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

#ifndef DLP_CREDENTIAL_SERVICE_DEFINES_H
#define DLP_CREDENTIAL_SERVICE_DEFINES_H
#include <stdint.h>

#define RESERVED_LEN 64

typedef enum {
    CLOUND_ACCOUNT = 1,   // 云账号
    DOMAIN_ACCOUNT,       // 域账号
    APPLICATION_ACCOUNT,  // 应用账号
} AccountType;

typedef struct {
    char* featureName;  // 首调者身份（包名或进程名），暂时为预留字段
    uint8_t* data;      // 待加密policy
    uint32_t dataLen;
    AccountType accountType;  // 发送端 & 接收端账号类型
    uint8_t reserved[RESERVED_LEN];
} DLP_PackPolicyParams;

typedef struct {
    char* featureName;  // 首调者身份（包名或进程名），暂时为预留字段
    uint8_t* data;      // policy密文
    uint32_t dataLen;
    uint8_t reserved[RESERVED_LEN];
} DLP_EncPolicyData;

typedef struct {
    uint8_t* data;  // policy明文
    uint32_t dataLen;
    uint8_t reserved[RESERVED_LEN];
} DLP_RestorePolicyData;

#endif