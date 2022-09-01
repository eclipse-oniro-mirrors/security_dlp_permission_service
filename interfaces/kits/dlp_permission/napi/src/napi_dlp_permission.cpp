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

#include "napi_dlp_permission.h"
#include "dlp_link_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "dlp_policy.h"
#include "dlp_file_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
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
    auto* asyncContext = new (std::nothrow) GenerateDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<GenerateDlpFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetGenerateDlpFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContextPtr.release();
    return result;
}

void NapiDlpPermission::GenerateDlpFileExcute(napi_env env, void* data)
{
    DLP_LOG_DEBUG(LABEL, "napi_create_async_work running");
    auto asyncContext = reinterpret_cast<GenerateDlpFileAsyncContext*>(data);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "asyncContext is nullptr");
        return;
    }
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpFileManager::GetInstance().GenerateDlpFile(
            asyncContext->plainTxtFd, asyncContext->cipherTxtFd, asyncContext->property, asyncContext->dlpFileNative);
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
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetOpenDlpFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode =
            DlpFileManager::GetInstance().OpenDlpFile(asyncContext->cipherTxtFd, asyncContext->dlpFileNative);
    }
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
    auto* asyncContext = new (std::nothrow) DlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetIsDlpFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode =
            DlpFileManager::GetInstance().IsDlpFile(asyncContext->cipherTxtFd, asyncContext->isDlpFile);
    }
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
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetDlpLinkFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode =
            DlpLinkManager::GetInstance().AddDlpLinkFile(asyncContext->dlpFileNative, asyncContext->linkFileName);
    }
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

napi_value NapiDlpPermission::DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo)
{
    auto* asyncContext = new (std::nothrow) DlpLinkFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpLinkFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetDlpLinkFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpLinkManager::GetInstance().DeleteDlpLinkFile(asyncContext->dlpFileNative);
    }
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
    auto* asyncContext = new (std::nothrow) RecoverDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<RecoverDlpFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetRecoverDlpFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode =
            DlpFileManager::GetInstance().RecoverDlpFile(asyncContext->dlpFileNative, asyncContext->plainFd);
    }
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
    auto* asyncContext = new (std::nothrow) CloseDlpFileAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<CloseDlpFileAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetCloseDlpFileParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpFileManager::GetInstance().CloseDlpFile(asyncContext->dlpFileNative);
    }
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
    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetInstallDlpSandboxParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpPermissionKit::InstallDlpSandbox(
            asyncContext->bundleName, asyncContext->permType, asyncContext->userId, asyncContext->appIndex);
    }
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
    auto* asyncContext = new (std::nothrow) DlpSandboxAsyncContext(env);
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "insufficient memory for asyncContext!");
        return nullptr;
    }
    std::unique_ptr<DlpSandboxAsyncContext> asyncContextPtr{asyncContext};
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetUninstallDlpSandboxParams(env, cbInfo, *asyncContext);
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
                       UninstallDlpSandboxComplete, (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpPermissionKit::UninstallDlpSandbox(
            asyncContext->bundleName, asyncContext->appIndex, asyncContext->userId);
    }
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
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetThirdInterfaceParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpPermissionKit::QueryDlpFileAccess(asyncContext->permType);
    }
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
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetThirdInterfaceParams(env, cbInfo, *asyncContext);
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
                       (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpPermissionKit::IsInDlpSandbox(asyncContext->inSandbox);
    }
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
    asyncContext->callbackRef = nullptr;
    if (asyncContext->errCode == DLP_OK) {
        GetThirdInterfaceParams(env, cbInfo, *asyncContext);
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
                       GetDlpSupportFileTypeComplete, (void*)asyncContext, &(asyncContext->work)));
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
    if (asyncContext->errCode == DLP_OK) {
        asyncContext->errCode = DlpPermissionKit::GetDlpSupportFileType(asyncContext->supportFileType);
    }
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
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[PARAM0]), desc));

    napi_property_descriptor descriptor[] = {DECLARE_NAPI_FUNCTION("dlpFile", DlpFile)};

    NAPI_CALL(
        env, napi_define_properties(env, exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("addDlpLinkFile", AddDlpLinkFile),
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
