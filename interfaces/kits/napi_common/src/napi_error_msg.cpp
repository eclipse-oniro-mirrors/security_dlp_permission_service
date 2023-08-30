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

#include <unordered_map>
#include "dlp_permission.h"
#include "napi_error_msg.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const std::unordered_map<int32_t, std::string> JS_ERROR_MSG_MAP = {
    //  error + message
    { ERR_JS_SUCCESS, "success" },
    { ERR_JS_PERMISSION_DENIED, "Permission denied" },
    { ERR_JS_NOT_SYSTEM_APP, "No permission to invoke this api, it is for system app" },
    { ERR_JS_PARAMETER_ERROR, "Parameter type error, please check parameter type" },
    { ERR_JS_CAPABILITY_NOT_SUPPORTED, "Capability is not supported" },
    { ERR_JS_INVALID_PARAMETER, "Parameter invalid, please check parameter range" },
    { ERR_JS_BEGIN_CREDENTIAL_FAIL,
      "Credential encryption or decryption busy, please wait for a moment and try again" },
    { ERR_JS_CREDENTIAL_TIMEOUT,
      "Credential encryption or decryption timeout, please wait for a moment and try again" },
    { ERR_JS_CREDENTIAL_SERVICE_ERROR, "Credential service error, please check the service and try again" },
    { ERR_JS_CREDENTIAL_SERVER_ERROR, "Credential server error, please check the server and try again" },
    { ERR_JS_API_ONLY_FOR_SANDBOX_ERROR, "No permission to invoke this api, it is only for DLP sandbox app" },
    { ERR_JS_API_NOT_FOR_SANDBOX_ERROR, "No permission to invoke this api, it is not for DLP sandbox app" },
    { ERR_JS_NOT_DLP_FILE, "Operate invalid DLP file, please use DLP file" },
    { ERR_JS_OPERATE_DLP_FILE_FAIL, "Operate DLP file fail, please check your permission and try again" },
    { ERR_JS_DLP_FILE_READ_ONLY, "DLP file is read only, please check your permission" },
    { ERR_JS_SYSTEM_SERVICE_EXCEPTION, "System service exception, please try again or reboot your device" },
    { ERR_JS_OUT_OF_MEMORY, "System out of memory, please try again or reboot your device" },
};

static const std::unordered_map<int32_t, int32_t> NATIVE_CODE_TO_JS_CODE_MAP = {
    { DLP_OK, ERR_JS_SUCCESS },

    // ERR_JS_PERMISSION_DENIED
    { DLP_SERVICE_ERROR_PERMISSION_DENY, ERR_JS_PERMISSION_DENIED },
    { DLP_SERVICE_ERROR_NOT_SYSTEM_APP, ERR_JS_NOT_SYSTEM_APP },

    // ERR_JS_INVALID_PARAMETER
    { DLP_SERVICE_ERROR_VALUE_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_VALUE_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_DIGEST_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_FD_ERROR, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_PTR_NULL, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_PARSE_ERROR_ACCOUNT_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_FUSE_ERROR_VALUE_INVALID, ERR_JS_INVALID_PARAMETER },
    { DLP_FUSE_ERROR_DLP_FILE_NULL, ERR_JS_INVALID_PARAMETER },

    // ERR_JS_BEGIN_CREDENTIAL_FAIL
    { DLP_SERVICE_ERROR_CREDENTIAL_BUSY, ERR_JS_BEGIN_CREDENTIAL_FAIL },
    { DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE, ERR_JS_BEGIN_CREDENTIAL_FAIL },

    // ERR_JS_CREDENTIAL_TIMEOUT
    { DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT, ERR_JS_CREDENTIAL_TIMEOUT },
    { DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR, ERR_JS_CREDENTIAL_TIMEOUT },

    // ERR_JS_CREDENTIAL_SERVICE_ERROR
    { DLP_CREDENTIAL_ERROR_COMMON_ERROR, ERR_JS_CREDENTIAL_SERVICE_ERROR },
    { DLP_CREDENTIAL_ERROR_HUKS_ERROR, ERR_JS_CREDENTIAL_SERVICE_ERROR },
    { DLP_CREDENTIAL_ERROR_IPC_ERROR, ERR_JS_CREDENTIAL_SERVICE_ERROR },

    // ERR_JS_CREDENTIAL_SERVER_ERROR
    { DLP_CREDENTIAL_ERROR_SERVER_ERROR, ERR_JS_CREDENTIAL_SERVER_ERROR },

    // ERR_JS_ACCOUNT_NOT_LOGIN
    { DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR, ERR_JS_ACCOUNT_NOT_LOGIN },

    // ERR_JS_USER_NO_PERMISSION
    { DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR, ERR_JS_USER_NO_PERMISSION },

    // ERR_JS_API_ONLY_FOR_SANDBOX_ERROR
    { DLP_NAPI_ERROR_API_ONLY_FOR_SANDBOX_ERROR, ERR_JS_API_ONLY_FOR_SANDBOX_ERROR },
    { DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR, ERR_JS_API_ONLY_FOR_SANDBOX_ERROR },

    // ERR_JS_API_NOT_FOR_SANDBOX_ERROR
    { DLP_NAPI_ERROR_API_NOT_FOR_SANDBOX_ERROR, ERR_JS_API_NOT_FOR_SANDBOX_ERROR },
    { DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR, ERR_JS_API_NOT_FOR_SANDBOX_ERROR },

    // ERR_JS_NOT_DLP_FILE
    { DLP_PARSE_ERROR_FILE_NOT_DLP, ERR_JS_NOT_DLP_FILE },
    { DLP_PARSE_ERROR_FILE_FORMAT_ERROR, ERR_JS_NOT_DLP_FILE },

    // ERR_JS_OPERATE_DLP_FILE_FAIL
    { DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_FUSE_ERROR_LINKFILE_EXIST, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_PARSE_ERROR_FILE_OPERATE_FAIL, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_PARSE_ERROR_FILE_LINKING, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_PARSE_ERROR_FILE_ALREADY_OPENED, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_PARSE_ERROR_FILE_NOT_OPENED, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_FUSE_ERROR_LINKFILE_NOT_EXIST, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_FUSE_ERROR_TOO_MANY_LINK_FILE, ERR_JS_OPERATE_DLP_FILE_FAIL },
    { DLP_LINK_FILE_NOT_ALLOW_OPERATE, ERR_JS_OPERATE_DLP_FILE_FAIL },

    // ERR_JS_DLP_FILE_READ_ONLY
    { DLP_PARSE_ERROR_FILE_READ_ONLY, ERR_JS_DLP_FILE_READ_ONLY },

    // ERR_JS_SYSTEM_SERVICE_EXCEPTION
    { DLP_NAPI_ERROR_NATIVE_BINDING_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_APPOBSERVER_NULL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_APPOBSERVER_ERROR, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_SERVICE_NOT_EXIST, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_CRYPT_FAIL, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, ERR_JS_SYSTEM_SERVICE_EXCEPTION },
    { DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, ERR_JS_SYSTEM_SERVICE_EXCEPTION },

    // ERR_JS_OUT_OF_MEMORY
    { DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, ERR_JS_OUT_OF_MEMORY },
    { DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, ERR_JS_OUT_OF_MEMORY },
    { DLP_FUSE_ERROR_MEMORY_OPERATE_FAIL, ERR_JS_OUT_OF_MEMORY },
};

std::string GetJsErrMsg(int32_t jsErrCode)
{
    auto iter = JS_ERROR_MSG_MAP.find(jsErrCode);
    if (iter != JS_ERROR_MSG_MAP.end()) {
        return iter->second;
    }
    std::string msg = "unkown error, please reboot your device and try again, error=" + std::to_string(jsErrCode);
    return msg;
}

int32_t NativeCodeToJsCode(int32_t nativeErrCode)
{
    auto iter = NATIVE_CODE_TO_JS_CODE_MAP.find(nativeErrCode);
    if (iter != NATIVE_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
