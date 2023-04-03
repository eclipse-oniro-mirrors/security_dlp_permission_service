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

#include "napi_dlp_permission.h"
#include "ability.h"
#include "ability_context.h"
#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "application_context.h"
#include "datashare_helper.h"
#include "dlp_link_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "dlp_policy.h"
#include "dlp_file_manager.h"
#include "ipc_skeleton.h"
#include "napi_error_msg.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "open.h"
#include "securec.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
RegisterDlpSandboxChangeInfo *g_dlpSandboxChangeInfoRegister = nullptr;
}  // namespace

static napi_value BindingJsWithNative(napi_env env, napi_value* argv, size_t argc)
{
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    if (napi_get_reference_value(env, dlpFileRef_, &constructor) != napi_ok) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "Get a reference to the global variable dlpFileRef_ complete");
    if (napi_new_instance(env, constructor, argc, argv, &instance) != napi_ok) {
        return nullptr;
    }
    DLP_LOG_DEBUG(LABEL, "New the js instance complete");
    return instance;
}

napi_value NapiDlpPermission::GenerateDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) GenerateDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GenerateDlpFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetGenerateDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GenerateDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GenerateDlpFileExcute, GenerateDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

static bool OpenFileByDatashare(std::string &uriStr, int32_t& fd)
{
    using namespace OHOS::FileManagement::ModuleFileIO;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    sptr<FileIoToken> remote = new (std::nothrow) IRemoteStub<FileIoToken>();
    if (remote == nullptr) {
        return false;
    }

    Uri uri(uriStr);
    dataShareHelper = DataShare::DataShareHelper::Creator(remote->AsObject(), MEDIALIBRARY_DATA_URI);
    if (dataShareHelper == nullptr) {
        return false;
    }
    fd = dataShareHelper->OpenFile(uri, std::string("rw"));
    if (fd < 0) {
        return false;
    }
    return true;
}

static void PrepareArgs(AAFwk::Want& want, std::vector<std::string>& list, GenerateDlpFileAsyncContext* asyncContext)
{
    want.SetAction("ohos.want.action.CREATE_FILE");
    list.push_back(asyncContext->fileName);
    want.SetParam("key_pick_file_name", list);
    want.SetParam("key_pick_file_location", 0);
    want.SetParam("key_pick_file_paths", std::string(""));
}

static int32_t PickDstFile(GenerateDlpFileAsyncContext* asyncContext)
{
    AAFwk::Want want;
    std::vector<std::string> list;
    PrepareArgs(want, list, asyncContext);

    AAFwk::StartOptions startOptions;
    startOptions.SetWindowMode(1);

    bool isCallBack = false;
    std::mutex parseMtx;
    std::condition_variable parseCv;
    std::string uri;
    AbilityRuntime::RuntimeTask task = [&isCallBack, &parseMtx, &parseCv, &uri](int32_t count,
        const AAFwk::Want& want, bool flag){
        std::vector<std::string> uriList = want.GetStringArrayParam("pick_path_return");
        if (uriList.size() > 0) {
            uri = uriList[0];
        }

        std::unique_lock<std::mutex> lck(parseMtx);
        isCallBack = true;
        parseCv.notify_all();
    };

    static uint32_t requestCode = 0;
    asyncContext->abilityContext->StartAbilityForResult(want, startOptions, requestCode++, std::move(task));
    {
        std::unique_lock<std::mutex> lck(parseMtx);
        if (!isCallBack) {
            parseCv.wait(lck);
        }
    }

    if (!isCallBack) {
        DLP_LOG_ERROR(LABEL, "fail to get uri callback:%{public}d", isCallBack);
        asyncContext->errCode = DLP_FILEPICK_NO_URI_RETURN;
        return -1;
    }

    if (uri.empty()) {
        DLP_LOG_ERROR(LABEL, "fail to get uri");
        asyncContext->errCode = DLP_FILEPICK_NO_URI_RETURN;
        return -1;
    }

    int32_t fd;
    bool ret = OpenFileByDatashare(uri, fd);
    if (!ret) {
        DLP_LOG_ERROR(LABEL, "open new file fail!");
        asyncContext->errCode = DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
        return -1;
    }
    return fd;
}

void NapiDlpPermission::GenerateDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GenerateDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    int result = DlpFileManager::GetInstance().GenerateDlpFilePrepare(asyncContext->property,
        asyncContext->dlpFileNative);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GenerateDlpFilePrepare fail");
        asyncContext->errCode = result;
        return;
    }

    int32_t fd;
    if (asyncContext->cipherTextFd == -1) {
        fd = PickDstFile(asyncContext);
        if (fd < 0) {
            return;
        }
    } else {
        fd = asyncContext->cipherTextFd;
    }

    asyncContext->errCode = DlpFileManager::GetInstance().GenerateDlpFileFinish(asyncContext->plainTxtFd,
        fd, asyncContext->dlpFileNative);

    if (asyncContext->cipherTextFd == -1) {
        close(fd);
    }
}

void NapiDlpPermission::GenerateDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GenerateDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GenerateDlpFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        napi_value nativeObjJs;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()), &nativeObjJs));

        napi_value dlpPropertyJs = DlpPropertyToJs(env, asyncContext->property);
        napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
        napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO);
        if (instance == nullptr) {
            DLP_LOG_ERROR(LABEL, "native instance binding fail");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        } else {
            resJs = instance;
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::OpenDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetOpenDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "OpenDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, OpenDlpFileExcute, OpenDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::OpenDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    auto context = AbilityRuntime::ApplicationContext::GetInstance();
    if (context == nullptr) {
        DLP_LOG_ERROR(LABEL, "get applicationContext fail");
        return;
    }

    std::string workDir = context->GetFilesDir();
    if (workDir.empty() || access(workDir.c_str(), 0) != 0) {
        DLP_LOG_ERROR(LABEL, "path is null or workDir doesn't exist");
        return;
    }

    asyncContext->errCode =
        DlpFileManager::GetInstance().OpenDlpFile(asyncContext->cipherTxtFd, asyncContext->dlpFileNative, workDir);
}

void NapiDlpPermission::OpenDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        napi_value nativeObjJs;
        if (asyncContext->dlpFileNative == nullptr) {
            DLP_LOG_ERROR(LABEL, "asyncContext dlpFileNative is nullptr");
            return;
        }
        NAPI_CALL_RETURN_VOID(
            env, napi_create_int64(env, reinterpret_cast<int64_t>(asyncContext->dlpFileNative.get()), &nativeObjJs));
        PermissionPolicy policy;
        asyncContext->dlpFileNative->GetPolicy(policy);
        std::string contactAccount;
        asyncContext->dlpFileNative->GetContactAccount(contactAccount);
        DlpProperty property = {
            .ownerAccount = policy.ownerAccount_,
            .authUsers = policy.authUsers_,
            .contractAccount = contactAccount,
            .ownerAccountType = policy.ownerAccountType_,
            .offlineAccess = asyncContext->dlpFileNative->GetOfflineAccess(),
        };

        napi_value dlpPropertyJs = DlpPropertyToJs(env, property);
        napi_value argv[PARAM_SIZE_TWO] = {nativeObjJs, dlpPropertyJs};
        napi_value instance = BindingJsWithNative(env, argv, PARAM_SIZE_TWO);
        if (instance == nullptr) {
            DLP_LOG_ERROR(LABEL, "native instance binding fail");
            asyncContext->errCode = DLP_NAPI_ERROR_NATIVE_BINDING_FAIL;
        } else {
            resJs = instance;
        }
    } else {
        if (asyncContext->dlpFileNative != nullptr) {
            std::string contactAccount = "";
            asyncContext->dlpFileNative->GetContactAccount(contactAccount);
            if (!contactAccount.empty()) {
                NAPI_CALL_RETURN_VOID(
                    env, napi_create_string_utf8(env, contactAccount.c_str(), NAPI_AUTO_LENGTH, &resJs));
            }
        }
    }

    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::IsDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetIsDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, IsDlpFileExcute, IsDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::IsDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpFileManager::GetInstance().IsDlpFile(asyncContext->cipherTxtFd, asyncContext->isDlpFile);
}

void NapiDlpPermission::IsDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};

    napi_value isDlpFileJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->isDlpFile, &isDlpFileJs));
    }

    ProcessCallbackOrPromise(env, asyncContext, isDlpFileJs);
}

napi_value NapiDlpPermission::AddDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, AddDlpLinkFileExcute, AddDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::AddDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().AddDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::AddDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::StopDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "StopDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, StopDlpLinkFileExcute, StopDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::StopDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().StopDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::StopDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RestartDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RestartDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, RestartDlpLinkFileExcute, RestartDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::RestartDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().RestartDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::RestartDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::ReplaceDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "ReplaceDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, ReplaceDlpLinkFileExcute, ReplaceDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::ReplaceDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpLinkManager::GetInstance().ReplaceDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
}

void NapiDlpPermission::ReplaceDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetDlpLinkFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "DeleteDlpLinkFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, DeleteDlpLinkFileExcute, DeleteDlpLinkFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::DeleteDlpLinkFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpLinkManager::GetInstance().DeleteDlpLinkFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::DeleteDlpLinkFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpLinkFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::RecoverDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) RecoverDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<RecoverDlpFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetRecoverDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RecoverDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, RecoverDlpFileExcute, RecoverDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::RecoverDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<RecoverDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode =
        DlpFileManager::GetInstance().RecoverDlpFile(asyncContext->dlpFileNative, asyncContext->plainFd);
}

void NapiDlpPermission::RecoverDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<RecoverDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<RecoverDlpFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::CloseDlpFile(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }
    auto* asyncContext = new (std::nothrow) CloseDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<CloseDlpFileAsyncContext> asyncContextPtr{asyncContext};

    if (!GetCloseDlpFileParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CloseDlpFile", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, CloseDlpFileExcute, CloseDlpFileComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::CloseDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<CloseDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpFileManager::GetInstance().CloseDlpFile(asyncContext->dlpFileNative);
}

void NapiDlpPermission::CloseDlpFileComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<CloseDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<CloseDlpFileAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::InstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};

    if (!GetInstallDlpSandboxParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "InstallDlpSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, InstallDlpSandboxExcute, InstallDlpSandboxComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::InstallDlpSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::InstallDlpSandbox(
        asyncContext->bundleName, asyncContext->permType, asyncContext->userId, asyncContext->appIndex);
}

void NapiDlpPermission::InstallDlpSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};
    napi_value appIndexJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, asyncContext->appIndex, &appIndexJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, appIndexJs);
}

napi_value NapiDlpPermission::UninstallDlpSandbox(napi_env env, napi_callback_info cbInfo)
{
    if (!IsSystemApp(env)) {
        return nullptr;
    }

    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};

    if (!GetUninstallDlpSandboxParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "UninstallDlpSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, UninstallDlpSandboxExcute,
        UninstallDlpSandboxComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::UninstallDlpSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::UninstallDlpSandbox(
        asyncContext->bundleName, asyncContext->appIndex, asyncContext->userId);
}

void NapiDlpPermission::UninstallDlpSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<DlpSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};
    napi_value resJs = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &resJs));
    ProcessCallbackOrPromise(env, asyncContext, resJs);
}

napi_value NapiDlpPermission::QueryFileAccess(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) QueryFileAccessAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<QueryFileAccessAsyncContext> asyncContextPtr{asyncContext};

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "QueryFileAccess", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, QueryFileAccessExcute, QueryFileAccessComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::QueryFileAccessExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<QueryFileAccessAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::QueryDlpFileAccess(asyncContext->permType);
}

void NapiDlpPermission::QueryFileAccessComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<QueryFileAccessAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<QueryFileAccessAsyncContext> asyncContextPtr{asyncContext};
    napi_value permTypeJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, asyncContext->permType, &permTypeJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, permTypeJs);
}

napi_value NapiDlpPermission::IsInSandbox(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) IsInSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<IsInSandboxAsyncContext> asyncContextPtr{asyncContext};

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsInSandbox", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, IsInSandboxExcute, IsInSandboxComplete,
        static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::IsInSandboxExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<IsInSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::IsInDlpSandbox(asyncContext->inSandbox);
}

void NapiDlpPermission::IsInSandboxComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<IsInSandboxAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<IsInSandboxAsyncContext> asyncContextPtr{asyncContext};
    napi_value inSandboxJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->inSandbox, &inSandboxJs));
    }
    ProcessCallbackOrPromise(env, asyncContext, inSandboxJs);
}

napi_value NapiDlpPermission::GetDlpSupportFileType(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) GetDlpSupportFileTypeAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GetDlpSupportFileTypeAsyncContext> asyncContextPtr{asyncContext};

    if (!GetThirdInterfaceParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        DLP_LOG_DEBUG(LABEL, "Create promise");
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        DLP_LOG_DEBUG(LABEL, "Undefined the result parameter");
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDlpSupportFileType", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetDlpSupportFileTypeExcute,
        GetDlpSupportFileTypeComplete, static_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GetDlpSupportFileTypeExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GetDlpSupportFileTypeAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }

    asyncContext->errCode = DlpPermissionKit::GetDlpSupportFileType(asyncContext->supportFileType);
}

void NapiDlpPermission::GetDlpSupportFileTypeComplete(napi_env env, napi_status status, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work complete");
    auto asyncContext = reinterpret_cast<GetDlpSupportFileTypeAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    std::unique_ptr<GetDlpSupportFileTypeAsyncContext> asyncContextPtr{asyncContext};
    napi_value supportFileTypeJs = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        supportFileTypeJs = VectorStringToJs(env, asyncContext->supportFileType);
    }
    ProcessCallbackOrPromise(env, asyncContext, supportFileTypeJs);
}

napi_value NapiDlpPermission::RegisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    RegisterDlpSandboxChangeInfo *registerDlpSandboxChangeInfo = new (std::nothrow) RegisterDlpSandboxChangeInfo();
    if (registerDlpSandboxChangeInfo == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<RegisterDlpSandboxChangeInfo> callbackPtr { registerDlpSandboxChangeInfo };
    if (!ParseInputToRegister(env, cbInfo, *registerDlpSandboxChangeInfo)) {
        return nullptr;
    }
    int32_t result = DlpPermissionKit::RegisterDlpSandboxChangeCallback(registerDlpSandboxChangeInfo->subscriber);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "RegisterSandboxChangeCallback failed");
        registerDlpSandboxChangeInfo->errCode = result;
        napi_throw(env, GenerateBusinessError(env, ERR_JS_ON_OFF_FAIL, GetJsErrMsg(ERR_JS_ON_OFF_FAIL)));
        return nullptr;
    }
    if (g_dlpSandboxChangeInfoRegister != nullptr) {
        delete g_dlpSandboxChangeInfoRegister;
        g_dlpSandboxChangeInfoRegister = nullptr;
    }
    g_dlpSandboxChangeInfoRegister = callbackPtr.release();
    return nullptr;
}

napi_value NapiDlpPermission::UnregisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    auto *asyncContext = new (std::nothrow) UnregisterSandboxChangeCallbackAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<UnregisterSandboxChangeCallbackAsyncContext> asyncContextPtr { asyncContext };
    if (!GetUnregisterSandboxParams(env, cbInfo, *asyncContext)) {
        return nullptr;
    }

    napi_value jsResult = nullptr;
    int32_t result = DlpPermissionKit::UnregisterDlpSandboxChangeCallback(asyncContext->result);
    bool isUnregisterSuccess = true;
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "UnregisterSandboxChangeCallback failed");
        napi_throw(env, GenerateBusinessError(env, ERR_JS_ON_OFF_FAIL, GetJsErrMsg(ERR_JS_ON_OFF_FAIL)));
        isUnregisterSuccess = false;
    }
    if (g_dlpSandboxChangeInfoRegister != nullptr) {
        delete g_dlpSandboxChangeInfoRegister;
        g_dlpSandboxChangeInfoRegister = nullptr;
    }
    napi_get_boolean(env, isUnregisterSuccess, &jsResult);
    return jsResult;
}

napi_value NapiDlpPermission::DlpFile(napi_env env, napi_callback_info cbInfo)
{
    napi_value instance = nullptr;
    napi_value constructor = nullptr;

    if (napi_get_reference_value(env, dlpFileRef_, &constructor) != napi_ok) {
        return nullptr;
    }

    DLP_LOG_DEBUG(LABEL, "Get a reference to the global variable dlpFileRef_ complete");

    if (napi_new_instance(env, constructor, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    DLP_LOG_DEBUG(LABEL, "New the js instance complete");

    return instance;
}

bool NapiDlpPermission::IsSystemApp(napi_env env)
{
    uint64_t fullTokenId = IPCSkeleton::GetSelfTokenID();
    bool isSystemApp = AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    if (!isSystemApp) {
        int32_t jsErrCode = ERR_JS_NOT_SYSTEM_APP;
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode))), false);
        return false;
    }
    return true;
}

napi_value NapiDlpPermission::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("generateDlpFile", GenerateDlpFile),
        DECLARE_NAPI_FUNCTION("openDlpFile", OpenDlpFile),
        DECLARE_NAPI_FUNCTION("isDlpFile", IsDlpFile),
        DECLARE_NAPI_FUNCTION("installDlpSandbox", InstallDlpSandbox),
        DECLARE_NAPI_FUNCTION("uninstallDlpSandbox", UninstallDlpSandbox),
        DECLARE_NAPI_FUNCTION("queryFileAccess", QueryFileAccess),
        DECLARE_NAPI_FUNCTION("isInSandbox", IsInSandbox),
        DECLARE_NAPI_FUNCTION("getDlpSupportFileType", GetDlpSupportFileType),
        DECLARE_NAPI_FUNCTION("on", RegisterSandboxChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterSandboxChangeCallback),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[PARAM0]), desc));

    napi_property_descriptor descriptor[] = {DECLARE_NAPI_FUNCTION("dlpFile", DlpFile)};

    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addDlpLinkFile", AddDlpLinkFile),
        DECLARE_NAPI_FUNCTION("stopDlpLinkFile", StopDlpLinkFile),
        DECLARE_NAPI_FUNCTION("restartDlpLinkFile", RestartDlpLinkFile),
        DECLARE_NAPI_FUNCTION("replaceDlpLinkFile", ReplaceDlpLinkFile),
        DECLARE_NAPI_FUNCTION("deleteDlpLinkFile", DeleteDlpLinkFile),
        DECLARE_NAPI_FUNCTION("recoverDlpFile", RecoverDlpFile),
        DECLARE_NAPI_FUNCTION("closeDlpFile", CloseDlpFile),
    };

    napi_value constructor = nullptr;
    NAPI_CALL(env, napi_define_class(env, DLP_FILE_CLASS_NAME.c_str(), DLP_FILE_CLASS_NAME.size(), JsConstructor,
                       nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &constructor));

    NAPI_CALL(env, napi_create_reference(env, constructor, 1, &dlpFileRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, DLP_FILE_CLASS_NAME.c_str(), constructor));

    CreateEnumAuthPermType(env, exports);
    CreateEnumAccountType(env, exports);

    return exports;
}

napi_value NapiDlpPermission::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[2] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr));
    int64_t nativeObjAddr;
    if (!GetInt64Value(env, argv[PARAM0], nativeObjAddr)) {
        return nullptr;
    }

    auto obj = reinterpret_cast<class DlpFile*>(nativeObjAddr);
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "obj is nullptr");
        return nullptr;
    }
    napi_status wrapStatus = napi_wrap(env, thisVar, obj,
        [](napi_env env, void* data, void* hint) {
            DLP_LOG_INFO(LABEL, "native obj destructed by js callback %{private}p", data);
            auto objInfo = reinterpret_cast<class DlpFile*>(data);
            if (objInfo != nullptr) {
                delete objInfo;
            }
        },
        nullptr, nullptr);
    if (wrapStatus != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Wrap js and native option failed");
    } else {
        DLP_LOG_INFO(LABEL, "native obj construct by %{private}p", obj);
    }
    if (argv[PARAM1] == nullptr) {
        DLP_LOG_ERROR(LABEL, "property is null");
    }
    NAPI_CALL(env, napi_set_named_property(env, thisVar, "dlpProperty", argv[PARAM1]));

    return thisVar;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    DLP_LOG_DEBUG(OHOS::Security::DlpPermission::LABEL, "Register end, start init.");

    return OHOS::Security::DlpPermission::NapiDlpPermission::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "dlpPermission",
    .nm_priv = ((void*)0),
    .reserved = {0}};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void DlpPermissionModuleRegister(void)
{
    napi_module_register(&_module);
}
