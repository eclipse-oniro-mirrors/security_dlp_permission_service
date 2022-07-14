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
    CREDENTIAL_OK = 0,
    PERMISSION_DENY = 1,
    GET_ACCOUNT_ERROR,
    MEM_OPERATE_FAIL,
    INVALID_VALUE,
} CredentialErrorNo;

typedef enum {
    CLOUD_ACCOUNT = 1,
    DOMAIN_ACCOUNT,
    APPLICATION_ACCOUNT,
} AccountType;

typedef struct {
    char* featureName;
    uint8_t* data;
    uint32_t dataLen;
    AccountType accountType;
    uint8_t reserved[RESERVED_LEN];
} DLP_PackPolicyParams;

typedef struct {
    char* featureName;
    uint8_t* data;
    uint32_t dataLen;
    uint8_t reserved[RESERVED_LEN];
} DLP_EncPolicyData;

typedef struct {
    uint8_t* data;
    uint32_t dataLen;
    uint8_t reserved[RESERVED_LEN];
} DLP_RestorePolicyData;

#endif