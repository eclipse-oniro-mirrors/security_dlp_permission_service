/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DLP_LOG_H
#define DLP_LOG_H

#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_BUFF_LEN (1024)

enum DlpLogLevel {
    DLP_LOG_LEVEL_I,
    DLP_LOG_LEVEL_E,
    DLP_LOG_LEVEL_W,
    DLP_LOG_LEVEL_D,
};

#define SELF_FREE_PTR(PTR, FREE_FUNC) \
    {                                 \
        if ((PTR) != NULL) {          \
            FREE_FUNC(PTR);           \
            (PTR) = NULL;             \
        }                             \
    }

#define DLP_FREE_PTR(p) SELF_FREE_PTR(p, DlpFree)
void *DlpMalloc(size_t size);
void DlpFree(void *ptr);
void DlpLog(uint32_t logLevel, const char *funcName, uint32_t lineNo, const char *format, ...);

#define DLP_LOG_I(...) DlpLog(DLP_LOG_LEVEL_I, __func__, __LINE__, __VA_ARGS__)
#define DLP_LOG_W(...) DlpLog(DLP_LOG_LEVEL_W, __func__, __LINE__, __VA_ARGS__)
#define DLP_LOG_E(...) DlpLog(DLP_LOG_LEVEL_E, __func__, __LINE__, __VA_ARGS__)
#define DLP_LOG_D(...) DlpLog(DLP_LOG_LEVEL_D, __func__, __LINE__, __VA_ARGS__)

enum DlpErrorCode {
    DLP_SUCCESS = 0,
    DLP_FAILURE = -1,
    DLP_ERROR_INVALID_ARGUMENT = -2,
    DLP_ERROR_MALLOC_FAIL = -3,
    DLP_ERROR_CRYPTO_ENGINE_ERROR = -4,
    DLP_ERROR_NULL_POINTER = -5,
    DLP_ERROR_NOT_SUPPORTED = -6,
    DLP_ERROR_INVALID_DIGEST = -7,
    DLP_ERROR_INVALID_FD = -8,
    DLP_ERROR_LSEEK_FAIL = -9,
    DLP_ERROR_READ_FAIL = -10,
    DLP_ERROR_WRITE_FAIL = -11,
    DLP_ERROR_CRYPT_FAIL = -12,
    DLP_ERROR_CRYPT_FILE_PARSE_FAIL = -13,
    DLP_ERROR_FILE_FAIL = -14,
    DLP_ERROR_NOT_DLP_FILE = -15,
    DLP_ERROR_INVALID_MODE = -16,
};

#ifdef __cplusplus
}
#endif
#endif
