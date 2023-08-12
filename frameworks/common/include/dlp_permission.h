/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <inttypes.h>
#include <string>
namespace OHOS {
namespace Security {
namespace DlpPermission {
enum DLPErrCode : int32_t {
    DLP_OK = 0,
    DLP_NAPI_ERROR_NATIVE_BINDING_FAIL = -1,
    DLP_NAPI_ERROR_API_ONLY_FOR_SANDBOX_ERROR = -2,
    DLP_NAPI_ERROR_API_NOT_FOR_SANDBOX_ERROR = -3,

    DLP_SERVICE_ERROR_VALUE_INVALID = -50,
    DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL = -51,
    DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL = -52,
    DLP_SERVICE_ERROR_JSON_OPERATE_FAIL = -53,
    DLP_SERVICE_ERROR_IPC_REQUEST_FAIL = -54,
    DLP_SERVICE_ERROR_PERMISSION_DENY = -55,
    DLP_SERVICE_ERROR_APPOBSERVER_NULL = -56,
    DLP_SERVICE_ERROR_APPOBSERVER_ERROR = -57,
    DLP_SERVICE_ERROR_CREDENTIAL_BUSY = -61,
    DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE = -62,
    DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT = -63,
    DLP_SERVICE_ERROR_SERVICE_NOT_EXIST = -64,
    DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL = -65,
    DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL = -66,
    DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL = -67,
    DLP_SERVICE_ERROR_NOT_SYSTEM_APP = -68,
    DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR = -69,
    DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR = -70,

    DLP_PARSE_ERROR_VALUE_INVALID = -100,
    DLP_PARSE_ERROR_DIGEST_INVALID = -101,
    DLP_PARSE_ERROR_FD_ERROR = -102,
    DLP_PARSE_ERROR_PTR_NULL = -103,
    DLP_PARSE_ERROR_FILE_NOT_DLP = -104,
    DLP_PARSE_ERROR_FILE_FORMAT_ERROR = -105,
    DLP_PARSE_ERROR_FILE_OPERATE_FAIL = -107,
    DLP_PARSE_ERROR_FILE_LINKING = -108,
    DLP_PARSE_ERROR_FILE_READ_ONLY = -109,
    DLP_PARSE_ERROR_FILE_ALREADY_OPENED = -110,
    DLP_PARSE_ERROR_FILE_NOT_OPENED = -111,
    DLP_PARSE_ERROR_CRYPT_FAIL = -112,
    DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR = -113,
    DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID = -114,
    DLP_PARSE_ERROR_ACCOUNT_INVALID = -115,
    DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL = -116,
    DLP_PARSE_ERROR_OPERATION_UNSUPPORTED = -117,
    DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE = -118,

    DLP_FUSE_ERROR_VALUE_INVALID = -200,
    DLP_FUSE_ERROR_DLP_FILE_NULL = -201,
    DLP_FUSE_ERROR_LINKFILE_EXIST = -202,
    DLP_FUSE_ERROR_LINKFILE_NOT_EXIST = -203,
    DLP_FUSE_ERROR_MEMORY_OPERATE_FAIL = -204,
    DLP_FUSE_ERROR_TOO_MANY_LINK_FILE = -205,
    DLP_LINK_FILE_NOT_ALLOW_OPERATE = -206,

    DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR = -300,
    DLP_CREDENTIAL_ERROR_COMMON_ERROR = -301,
    DLP_CREDENTIAL_ERROR_HUKS_ERROR = -302,
    DLP_CREDENTIAL_ERROR_IPC_ERROR = -303,
    DLP_CREDENTIAL_ERROR_SERVER_ERROR = -304,
    DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR = -305,
    DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR = -306,

    DLP_CALLBACK_EXCEEDED_MAXNUM_REGISTRATION_LIMIT_ERROR = -401,
    DLP_CALLBACK_PARAM_INVALID = -402,
    DLP_CALLBACK_SA_WORK_ABNORMAL = -403,
    DLP_CALLBACK_INTERFACE_NOT_USED_TOGETHER = -404,

    DLP_RETENTION_FILE_FIND_FILE_ERROR = -500,
    DLP_RETENTION_COMMON_FILE_OPEN_FAILED = -501,
    DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY = -502,
    DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_DATA_EMPTY = -503,
    DLP_RETENTION_MAP_INFO_EMPTY_ERROR = -504,
    DLP_INSERT_FILE_ERROR = -505,
    DLP_RETENTION_UPDATE_ERROR = -506,
    DLP_RETENTION_SERVICE_ERROR = -507,
    DLP_FILE_NO_NEED_UPDATE = -508,
    DLP_RETENTION_NOT_ALLOW_UNINSTALL = -509,
    DLP_JSON_UPDATE_ERROR = -510,
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // FRAMEWORKS_COMMON_DLP_PERMISSION_H
