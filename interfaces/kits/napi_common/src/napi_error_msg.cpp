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

#include "dlp_permission.h"
#include "napi_error_msg.h"
#include <unordered_map>

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const std::unordered_map<int32_t, std::string> g_dlpErrMsg = {
    //  error + message
    {
        DLP_OK,
        "success",
    },
    {
        DLP_NAPI_ERROR_PERMISSION_DENY,
        "napi error, no permission to invoke this api",
    },
    {
        DLP_NAPI_ERROR_PARSE_JS_PARAM,
        "napi error, parse js param fail",
    },
    {
        DLP_NAPI_ERROR_THIS_VALUE_NULL,
        "napi error, receive js this arg fail",
    },
    {
        DLP_NAPI_ERROR_UNWRAP_FAIL,
        "napi error, unwarp native instance fail",
    },
    {
        DLP_NAPI_ERROR_NATIVE_BINDING_FAIL,
        "napi error, binding js instance and native instance fail",
    },
    {
        DLP_SERVICE_ERROR_VALUE_INVALID,
        "service error, input param invalid",
    },
    {
        DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL,
        "service error, parcel operate fail",
    },
    {
        DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL,
        "service error, memory operate fail",
    },
    {
        DLP_SERVICE_ERROR_JSON_OPERATE_FAIL,
        "service error, json operate fail",
    },
    {
        DLP_SERVICE_ERROR_IPC_REQUEST_FAIL,
        "service error, ipc request fail",
    },
    {
        DLP_SERVICE_ERROR_PERMISSION_DENY,
        "service error, permission denied",
    },
    {
        DLP_SERVICE_ERROR_APPOBSERVER_NULL,
        "service error, app observer is null",
    },
    {
        DLP_SERVICE_ERROR_APPOBSERVER_ERROR,
        "service error, app observer error",
    },
    {
        DLP_SERVICE_ERROR_CREDENTIAL_OPERATE_FAIL,
        "service error, credential operate fail",
    },
    {
        DLP_SERVICE_ERROR_CREDENTIAL_BUSY,
        "service error, credential busy",
    },
    {
        DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE,
        "service error, credential task duplicate",
    },
    {
        DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT,
        "service error, credential task timeout",
    },
    {
        DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL,
        "service error, get account info fail",
    },

    {
        DLP_PARSE_ERROR_VALUE_INVALID,
        "parse error, input param invalid",
    },
    {
        DLP_PARSE_ERROR_DIGEST_INVALID,
        "parse error, input digest invalid",
    },
    {
        DLP_PARSE_ERROR_FD_ERROR,
        "parse error, input fd invalid",
    },
    {
        DLP_PARSE_ERROR_PTR_NULL,
        "parse error, input ptr is null",
    },
    {
        DLP_PARSE_ERROR_FILE_NOT_DLP,
        "parse error, file is not dlp",
    },
    {
        DLP_PARSE_ERROR_FILE_FORMAT_ERROR,
        "parse error, file format error",
    },
    {
        DLP_PARSE_ERROR_FILE_UNPARSED,
        "parse error, file unparsed",
    },
    {
        DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        "parse error, file openrate fail",
    },
    {
        DLP_PARSE_ERROR_FILE_LINKING,
        "parse error, file is linking",
    },
    {
        DLP_PARSE_ERROR_FILE_READ_ONLY,
        "parse error, file is read only",
    },
    {
        DLP_PARSE_ERROR_FILE_ALREADY_OPENED,
        "parse error, file is already opened",
    },
    {
        DLP_PARSE_ERROR_FILE_NOT_OPENED,
        "parse error, request file is not opened",
    },
    {
        DLP_PARSE_ERROR_CRYPT_FAIL,
        "parse error, crypt fail",
    },
    {
        DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        "parse error, crypto engine error",
    },
    {
        DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID,
        "parse error, cipher params invalid",
    },
    {
        DLP_PARSE_ERROR_ACCOUNT_INVALID,
        "parse error, account is invalid",
    },
    {
        DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        "parse error, memory operate fail",
    },
    {
        DLP_PARSE_ERROR_OPERATION_UNSUPPORTED,
        "parse error, operation unsupported",
    },
    {
        DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE,
        "parse error, open dlp files are too many",
    },

    {
        DLP_FUSE_ERROR_VALUE_INVALID,
        "link fuse error, input param invalid",
    },
    {
        DLP_FUSE_ERROR_DLP_FILE_NULL,
        "link fuse error, dlp file is null",
    },
    {
        DLP_FUSE_ERROR_LINKFILE_EXIST,
        "link fuse error, link file is exist",
    },
    {
        DLP_FUSE_ERROR_LINKFILE_NOT_EXIST,
        "link fuse error, link file is not exist",
    },
    {
        DLP_FUSE_ERROR_MEMORY_OPERATE_FAIL,
        "link fuse error, memory operate fail",
    },
    {
        DLP_FUSE_ERROR_TOO_MANY_LINK_FILE,
        "link fuse error, link files are too many",
    },
};

std::string GetErrStr(int32_t errNo)
{
    auto iter = g_dlpErrMsg.find(errNo);
    if (iter != g_dlpErrMsg.end()) {
        return iter->second;
    }
    std::string msg = "unkown error, error num: " + std::to_string(errNo);
    return msg;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
