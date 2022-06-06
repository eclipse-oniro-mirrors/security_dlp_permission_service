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

#ifndef  INTERFACES_KITS_DLP_FUSE_NAPI_INCLUDE_NAPI_H
#define  INTERFACES_KITS_DLP_FUSE_NAPI_INCLUDE_NAPI_H

#include "fuse_daemon.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
const int DLP_FUSE_OPERA_FAIL = -1;
const int DLP_FUSE_OPERA_SUCC = 0;
const int VALUE_BUFFER_SIZE = 256;

const int STRING_LEN_LIMIT = 256;
const int FUSE_DEV_FD = 1000;

struct DlpFuseAsyncContext {
    napi_env env = nullptr;
    int result = DLP_FUSE_OPERA_FAIL; // default failed

    std::string deleteDlpLinkName;
    struct DlpFuseParam params;

    napi_deferred   deferred = nullptr; // promise handle
    napi_ref        callbackRef = nullptr; // callback handle
    napi_async_work work = nullptr; // work handle
};

class NapiDlpFuse {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static void InitDlpFuseExcute(napi_env env, void *data);
    static void InitDlpFuseComplete(napi_env env, napi_status status, void *data);
    static napi_value InitDlpFuse(napi_env env, napi_callback_info info);
    static void GetInitDlpFuseParams(const napi_env env, const napi_callback_info info,
        DlpFuseAsyncContext& asyncContext);

    static void GetCallback(const napi_env env, napi_value argv, DlpFuseAsyncContext& asyncContext);
    static void ReplyNapiInterfaceStatus(napi_env env, napi_status status, void *data);

    static int32_t GetIntProp(napi_env env, napi_value object, const std::string& propName);
    static std::string GetStringProp(napi_env env, napi_value object, const std::string &propertyName);
    static napi_status GetUint8ArrayProp(napi_env env, napi_value object, const std::string &propertyName,
        unsigned char **array, size_t *arrayLen);

    static bool GetBoolProp(napi_env env, napi_value object, const std::string& propName);
    static void GetDlpFuseParams(const napi_env env, const napi_callback_info info,
        DlpFuseAsyncContext& asyncContext);
    static void SetDlpFuseFileExcute(napi_env env, void *data);
    static void SetDlpFuseFileComplete(napi_env env, napi_status status, void *data);
    static napi_value SetDlpFuseFile(napi_env env, napi_callback_info info);

    static void DeleteDlpFuseFileExcute(napi_env env, void *data);
    static void DeleteDlpFuseFileComplete(napi_env env, napi_status status, void *data);
    static napi_value DeleteDlpFuseFile(napi_env env, napi_callback_info info);
    static void GetDeleteDlpFuseParams(const napi_env env, const napi_callback_info info,
        DlpFuseAsyncContext& asyncContext);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  INTERFACES_KITS_DLP_FUSE_NAPI_INCLUDE_NAPI_H */
