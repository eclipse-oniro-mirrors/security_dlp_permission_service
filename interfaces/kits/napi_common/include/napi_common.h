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

#ifndef INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H
#define INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H

#include <vector>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "dlp_file.h"
#include "dlp_policy.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM_SIZE_ONE = 1;
constexpr int32_t PARAM_SIZE_TWO = 2;
constexpr int32_t PARAM_SIZE_THREE = 3;
constexpr int32_t PARAM_SIZE_FOUR = 4;

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env napiEnv);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
    napi_ref callbackRef = nullptr;    // callback handle
    napi_async_work work = nullptr;    // work handle
};

struct GenerateDlpFileAsyncContext : public CommonAsyncContext {
    explicit GenerateDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env){};
    int64_t plainTxtFd;
    int64_t cipherTxtFd;
    DlpProperty property;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct DlpFileAsyncContext : public CommonAsyncContext {
    explicit DlpFileAsyncContext(napi_env env) : CommonAsyncContext(env){};
    int64_t cipherTxtFd;
    DlpProperty property;
    bool isDlpFile = false;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct DlpLinkFileAsyncContext : public CommonAsyncContext {
    explicit DlpLinkFileAsyncContext(napi_env env) : CommonAsyncContext(env){};
    std::string linkFileName = "";
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct RecoverDlpFileAsyncContext : public CommonAsyncContext {
    explicit RecoverDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env){};
    int64_t plainFd = 0;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct CloseDlpFileAsyncContext : public CommonAsyncContext {
    explicit CloseDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env){};
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};


bool CheckPermission();
napi_value CreateEnumAuthPermType(napi_env env, napi_value exports);
napi_value CreateEnumAccountType(napi_env env, napi_value exports);
void CreateNapiRetMsg(napi_env env, int32_t errorCode, napi_value* result);
void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext* asyncContext, napi_value data);

void GetGenerateDlpFileParams(
    const napi_env env, const napi_callback_info info, GenerateDlpFileAsyncContext& asyncContext);
void GetOpenDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext);
void GetIsDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext);

void GetDlpLinkFileParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext);
void GetRecoverDlpFileParams(
    const napi_env env, const napi_callback_info info, RecoverDlpFileAsyncContext& asyncContext);
void GetCloseDlpFileParams(const napi_env env, const napi_callback_info info, CloseDlpFileAsyncContext& asyncContext);

bool GetDlpProperty(napi_env env, napi_value object, DlpProperty& property);
void GetCallback(const napi_env env, napi_value jsObject, CommonAsyncContext& asyncContext);

napi_value GetNapiValue(napi_env env, napi_value jsObject, const std::string& key);
bool GetStringValue(napi_env env, napi_value jsObject, std::string& result);
bool GetStringValueByKey(napi_env env, napi_value jsObject, const std::string& key, std::string& result);
bool GetInt64Value(napi_env env, napi_value jsObject, int64_t& result);
bool GetInt64ValueByKey(napi_env env, napi_value jsObject, const std::string& key, int64_t& result);
bool GetUint32Value(napi_env env, napi_value jsObject, uint32_t& result);
bool GetUint32ValueByKey(napi_env env, napi_value jsObject, const std::string& key, uint32_t& result);
napi_value GetArrayValueByKey(napi_env env, napi_value jsObject, const std::string& key);
bool GetVectorAuthUser(napi_env env, napi_value jsObject, std::vector<AuthUserInfo>& resultVec);
bool GetVectorAuthUserByKey(
    napi_env env, napi_value jsObject, const std::string& key, std::vector<AuthUserInfo>& resultVec);
napi_value DlpPropertyToJs(napi_env env, const DlpProperty& property);
napi_value VectorAuthUserToJs(napi_env env, const std::vector<AuthUserInfo>& users);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H */
