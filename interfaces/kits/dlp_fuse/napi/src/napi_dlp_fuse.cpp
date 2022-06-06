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

#include "napi_dlp_fuse.h"

#include "dlp_permission_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFuseNapi"
};
} // namespace

static const int ARG_TWO = 2;

void NapiDlpFuse::GetCallback(const napi_env env, napi_value argv, DlpFuseAsyncContext& asyncContext)
{
    napi_valuetype valueType;
    napi_typeof(env, argv, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv, 1, &asyncContext.callbackRef);
    } else {
        DLP_LOG_ERROR(LABEL, "get callback failed");
    }
}

void NapiDlpFuse::GetInitDlpFuseParams(const napi_env env, const napi_callback_info info,
    DlpFuseAsyncContext& asyncContext)
{
    size_t argc = 1;
    napi_value argv = nullptr;
    napi_get_cb_info(env, info, &argc, &argv, NULL, NULL);
    if (argc == 1) {
        GetCallback(env, argv, asyncContext);
    }
}

void NapiDlpFuse::InitDlpFuseExcute(napi_env env, void *data)
{
    DlpFuseAsyncContext* asyncContext = (DlpFuseAsyncContext *)data;
    asyncContext->result = FuseDaemon::InitFuseFs(FUSE_DEV_FD);
}

void NapiDlpFuse::ReplyNapiInterfaceStatus(napi_env env, napi_status status, void *data)
{
    DlpFuseAsyncContext *asyncContext = (DlpFuseAsyncContext *)data;
    napi_value result;
    napi_create_int32(env, asyncContext->result, &result);

    if (asyncContext->deferred) {
        // promise type
        if (asyncContext->result == DLP_FUSE_OPERA_SUCC) {
            // exec success
            napi_resolve_deferred(env, asyncContext->deferred, result);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, result);
        }
    } else {
        // callback type
        napi_value callback = nullptr;
        napi_value thisValue = nullptr; // recv napi value
        napi_value thatValue = nullptr; // result napi value

        // set call function params->napi_call_function(env, recv, func, argc, argv, result)
        napi_get_undefined(env, &thisValue); // can not null otherwise js code can not get return
        napi_create_int32(env, 0, &thatValue); // can not null otherwise js code can not get return
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, thisValue, callback, 1, &result, &thatValue);
        napi_delete_reference(env, asyncContext->callbackRef); // release callback handle
    }

    // after return the result, free resources
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

void NapiDlpFuse::InitDlpFuseComplete(napi_env env, napi_status status, void *data)
{
    ReplyNapiInterfaceStatus(env, status, data);
}

napi_value NapiDlpFuse::InitDlpFuse(napi_env env, napi_callback_info info)
{
    auto *asyncContext = new DlpFuseAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    GetInitDlpFuseParams(env, info, *asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result); // create delay promise object
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "InitDlpFuse", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource, InitDlpFuseExcute, InitDlpFuseComplete,
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    return result;
}

bool NapiDlpFuse::GetBoolProp(napi_env env, napi_value object, const std::string& propName)
{
    bool intValue = false;
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        napi_status getIntStatus = napi_get_value_bool(env, value, &intValue);
        if (getIntStatus == napi_ok) {
            return intValue;
        }
    }
    return intValue;
}


int32_t NapiDlpFuse::GetIntProp(napi_env env, napi_value object, const std::string& propName)
{
    int32_t intValue = -1;
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        napi_status getIntStatus = napi_get_value_int32(env, value, &intValue);
        if (getIntStatus == napi_ok) {
            return intValue;
        }
    }
    return intValue;
}

std::string NapiDlpFuse::GetStringProp(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propertyName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        char chars[STRING_LEN_LIMIT] = {0};
        size_t charLength = 0;
        napi_status getStringStatus =
            napi_get_value_string_utf8(env, value, chars, STRING_LEN_LIMIT, &charLength);
        if (getStringStatus == napi_ok && charLength > 0) {
            return std::string(chars, charLength);
        }
    }
    return "";
}

napi_status NapiDlpFuse::GetUint8ArrayProp(napi_env env, napi_value object,
    const std::string &propertyName, unsigned char **array, size_t *arrayLen)
{
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propertyName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        napi_value input_buffer = nullptr;
        size_t byte_offset = 0;
        napi_typedarray_type type;
        napi_get_typedarray_info(env, value, &type, arrayLen, (void **)array, &input_buffer, &byte_offset);
        if (type != napi_uint8_array || *array == nullptr) {
            DLP_LOG_ERROR(LABEL, "is not uint8 array");
            return napi_array_expected;
        }
        return napi_ok;
    }
    return napi_array_expected;
}

void NapiDlpFuse::GetDlpFuseParams(const napi_env env, const napi_callback_info info,
    DlpFuseAsyncContext& asyncContext)
{
    size_t argc = ARG_TWO;

    napi_value argv[ARG_TWO] = {nullptr};

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    asyncContext.env = env;

    asyncContext.params.dlpFileFd = GetIntProp(env, argv[0], "dlpFileFd");
    if (asyncContext.params.dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is error");
        return;
    }
    std::string linkName = GetStringProp(env, argv[0], "dlpLinkName");
    if (linkName == "" || linkName.length() >= MAX_FILE_NAME_LEN) {
        DLP_LOG_ERROR(LABEL, "link file path name is failed");
        return;
    }
    asyncContext.params.dlpLinkName = linkName;
    std::string cryptAlgo = GetStringProp(env, argv[0], "cryptAlgo"); // using string is easy to add new type.
    if (cryptAlgo != "aes_ctr") {
        DLP_LOG_ERROR(LABEL, "unknown crypt algo %{public}s", cryptAlgo.c_str());
        return;
    }
    asyncContext.params.cryptAlgo = AES_CTR;

    napi_status status = GetUint8ArrayProp(env, argv[0], "cryptKey",
        &asyncContext.params.key, &asyncContext.params.keyLen);
    if (status != napi_ok) {
        DLP_LOG_ERROR(LABEL, "get crypt key failed");
        return;
    }
    asyncContext.params.isReadOnly = GetBoolProp(env, argv[0], "isReadonly");

    if (argc == ARG_TWO) {
        GetCallback(env, argv[1], asyncContext);
    }

    asyncContext.result = DLP_FUSE_OPERA_SUCC;
    DLP_LOG_DEBUG(LABEL, "dlpFileFd = %{public}d, dlpLinkName = %{public}s, cryptAlgo = %{public}d, keyLen %{public}zu",
        asyncContext.params.dlpFileFd, asyncContext.params.dlpLinkName.c_str(),
        asyncContext.params.cryptAlgo, asyncContext.params.keyLen);
}

void NapiDlpFuse::SetDlpFuseFileExcute(napi_env env, void *data)
{
    DlpFuseAsyncContext* asyncContext = (DlpFuseAsyncContext *)data;
    asyncContext->result =
        (FuseDaemon::AddDlpLinkRelation(&asyncContext->params) == 0) ? DLP_FUSE_OPERA_SUCC : DLP_FUSE_OPERA_FAIL;
    DLP_LOG_DEBUG(LABEL, "SetDlpFuseFileExcute res %{public}d", asyncContext->result);
}

void NapiDlpFuse::SetDlpFuseFileComplete(napi_env env, napi_status status, void *data)
{
    ReplyNapiInterfaceStatus(env, status, data);
}

napi_value NapiDlpFuse::SetDlpFuseFile(napi_env env, napi_callback_info info)
{
    DLP_LOG_ERROR(LABEL, "SetDlpFuseFile.");
    auto *asyncContext = new DlpFuseAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    GetDlpFuseParams(env, info, *asyncContext);
    if (asyncContext->result == DLP_FUSE_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        DLP_LOG_ERROR(LABEL, "SetDlpFuseFile undefined.");
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "SetDlpFuseFile", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource, SetDlpFuseFileExcute, SetDlpFuseFileComplete,
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result
    return result;
}

void NapiDlpFuse::GetDeleteDlpFuseParams(const napi_env env, const napi_callback_info info,
    DlpFuseAsyncContext& asyncContext)
{
    size_t argc = ARG_TWO;

    napi_value argv[ARG_TWO] = {nullptr};

    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    asyncContext.env = env;

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    if (valueType == napi_string) {
        char chars[STRING_LEN_LIMIT] = {0};
        size_t charLength = 0;
        napi_status getStringStatus =
            napi_get_value_string_utf8(env, argv[0], chars, STRING_LEN_LIMIT, &charLength);
        if (getStringStatus == napi_ok && charLength > 0) {
            asyncContext.deleteDlpLinkName = std::string(chars, charLength);
        } else {
            asyncContext.result = DLP_FUSE_OPERA_FAIL;
            DLP_LOG_ERROR(LABEL, "param error, get linkfile name failed");
        }
    } else {
        asyncContext.result = DLP_FUSE_OPERA_FAIL;
        DLP_LOG_ERROR(LABEL, "param type error, get linkfile name failed");
        return;
    }

    if (argc == ARG_TWO) {
        GetCallback(env, argv[1], asyncContext);
    }

    asyncContext.result = DLP_FUSE_OPERA_SUCC;
}


void NapiDlpFuse::DeleteDlpFuseFileExcute(napi_env env, void *data)
{
    DlpFuseAsyncContext* asyncContext = (DlpFuseAsyncContext *)data;
    FuseDaemon::DelDlpLinkRelation(asyncContext->deleteDlpLinkName);
    asyncContext->result = DLP_FUSE_OPERA_SUCC;
    DLP_LOG_DEBUG(LABEL, "DeleteDlpFuseFileExcute res %{public}d", asyncContext->result);
}

void NapiDlpFuse::DeleteDlpFuseFileComplete(napi_env env, napi_status status, void *data)
{
    ReplyNapiInterfaceStatus(env, status, data);
}

napi_value NapiDlpFuse::DeleteDlpFuseFile(napi_env env, napi_callback_info info)
{
    auto *asyncContext = new DlpFuseAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        DLP_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    GetDeleteDlpFuseParams(env, info, *asyncContext);
    if (asyncContext->result == DLP_FUSE_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "DeleteDlpFuseFile", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource, DeleteDlpFuseFileExcute, DeleteDlpFuseFileComplete,
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result
    return result;
}


napi_value NapiDlpFuse::Init(napi_env env, napi_value exports)
{
    DLP_LOG_DEBUG(LABEL, "enter init.");

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("initDlpFuse", InitDlpFuse),
        DECLARE_NAPI_FUNCTION("setDlpFuseFile", SetDlpFuseFile),
        DECLARE_NAPI_FUNCTION("deleteDlpFuseFile", DeleteDlpFuseFile),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
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

    return OHOS::Security::DlpPermission::NapiDlpFuse::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "dlpFuse",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void DlpFuseModuleRegister(void)
{
    napi_module_register(&_module);
}
