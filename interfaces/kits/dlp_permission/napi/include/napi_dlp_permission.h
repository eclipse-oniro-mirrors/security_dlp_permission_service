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

#ifndef INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H
#define INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H

#include "dlp_permission_callback.h"
#include "dlp_policy.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static thread_local napi_ref dlpFileRef_;
const std::string DLP_FILE_CLASS_NAME = "dlpFile";
const int STRING_LEN_LIMIT = 1024;

class NapiDlpPermission {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static napi_value DlpFile(napi_env env, napi_callback_info cbInfo);

    static void GenerateDlpFileExcute(napi_env env, void* data);
    static void GenerateDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value GenerateDlpFile(napi_env env, napi_callback_info cbInfo);

    static void OpenDlpFileExcute(napi_env env, void* data);
    static void OpenDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value OpenDlpFile(napi_env env, napi_callback_info cbInfo);

    static void IsDlpFileExcute(napi_env env, void* data);
    static void IsDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value IsDlpFile(napi_env env, napi_callback_info cbInfo);

    static void AddDlpLinkFileExcute(napi_env env, void* data);
    static void AddDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value AddDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void DeleteDlpLinkFileExcute(napi_env env, void* data);
    static void DeleteDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void RecoverDlpFileExcute(napi_env env, void* data);
    static void RecoverDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value RecoverDlpFile(napi_env env, napi_callback_info cbInfo);

    static void CloseDlpFileExcute(napi_env env, void* data);
    static void CloseDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value CloseDlpFile(napi_env env, napi_callback_info cbInfo);

    static void InstallDlpSandboxExcute(napi_env env, void* data);
    static void InstallDlpSandboxComplete(napi_env env, napi_status status, void* data);
    static napi_value InstallDlpSandbox(napi_env env, napi_callback_info cbInfo);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H */