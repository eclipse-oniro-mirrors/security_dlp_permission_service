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

#ifndef FRAMEWORKS_COMMON_DLP_PERMISSION_H
#define FRAMEWORKS_COMMON_DLP_PERMISSION_H

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum DLPErrCode : int32_t {
    DLP_OK = 0,
    DLP_NAPI_ERROR_PARSE_JS_PARAM = -1,
    DLP_NAPI_ERROR_THIS_VALUE_NULL = -2,
    DLP_NAPI_ERROR_UNWRAP_FAIL = -3,
    DLP_NAPI_ERROR_NATIVE_OBJ_NULL = -4,
    DLP_NAPI_ERROR_NATIVE_DINDING_FAIL = -5,

    DLP_SERVICE_ERROR_VALUE_INVALID = -50,
    DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL = -51,
    DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL = -52,
    DLP_SERVICE_ERROR_JSON_OPERATE_FAIL = -53,
    DLP_SERVICE_ERROR_IPC_REQUEST_FAIL = -54,
    DLP_SERVICE_ERROR_CREDENTIAL_OPERATE_FAIL = -55,
    DLP_SERVICE_ERROR_CREDENTIAL_BUSY = -56,
    DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE = -57,
    DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT = -58,

    DLP_PARSE_ERROR_VALUE_INVALID = -100,
    DLP_PARSE_ERROR_DIGEST_INVALID = -101,
    DLP_PARSE_ERROR_FD_ERROR = -102,
    DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL = -103,
    DLP_PARSE_ERROR_OPERATION_UNSUPPORTED = -104,
    DLP_PARSE_ERROR_FILE_NOT_DLP = -105,
    DLP_PARSE_ERROR_FILE_FORMAT_ERROR = -106,
    DLP_PARSE_ERROR_FILE_UNPARSED = -107,
    DLP_PARSE_ERROR_FILE_OPERATE_FAIL = -108,
    DLP_PARSE_ERROR_CRYPT_FAIL = -109,
    DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR = -110,
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // FRAMEWORKS_COMMON_DLP_PERMISSION_H
