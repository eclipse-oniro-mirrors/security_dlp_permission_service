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

#include "napi_common.h"
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "napi_error_msg.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
}  // namespace

CommonAsyncContext::CommonAsyncContext(napi_env napiEnv)
{
    env = napiEnv;
}

CommonAsyncContext::~CommonAsyncContext()
{
    if (callbackRef) {
        DLP_LOG_DEBUG(LABEL, "~CommonAsyncContext delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (work) {
        DLP_LOG_DEBUG(LABEL, "~CommonAsyncContext delete work");
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

static napi_value EnumAuthPermTypeConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data));
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));
    return thisArg;
}

napi_value CreateEnumAuthPermType(napi_env env, napi_value exports)
{
    napi_value readOnly = nullptr;
    napi_value fullControl = nullptr;

    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(READ_ONLY), &readOnly));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(FULL_CONTROL), &fullControl));

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("READ_ONLY", readOnly),
        DECLARE_NAPI_STATIC_PROPERTY("FULL_CONTROL", fullControl),
    };
    napi_value result = nullptr;
    NAPI_CALL(env, napi_define_class(env, "AuthPermType", NAPI_AUTO_LENGTH, EnumAuthPermTypeConstructor, nullptr,
                       sizeof(desc) / sizeof(*desc), desc, &result));

    NAPI_CALL(env, napi_set_named_property(env, exports, "AuthPermType", result));
    return exports;
}

static napi_value EnumAccountTypeConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data));
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));
    return thisArg;
}

napi_value CreateEnumAccountType(napi_env env, napi_value exports)
{
    napi_value cloudAccount = nullptr;
    napi_value domainAccount = nullptr;
    napi_value appAccount = nullptr;

    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(CLOUD_ACCOUNT), &cloudAccount));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DOMAIN_ACCOUNT), &domainAccount));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(APPLICATION_ACCOUNT), &appAccount));

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CLOUD_ACCOUNT", cloudAccount),
        DECLARE_NAPI_STATIC_PROPERTY("DOMAIN_ACCOUNT", domainAccount),
        DECLARE_NAPI_STATIC_PROPERTY("APPLICATION_ACCOUNT", domainAccount),
    };
    napi_value result = nullptr;
    NAPI_CALL(env, napi_define_class(env, "AccountType", NAPI_AUTO_LENGTH, EnumAccountTypeConstructor, nullptr,
                       sizeof(desc) / sizeof(*desc), desc, &result));

    NAPI_CALL(env, napi_set_named_property(env, exports, "AccountType", result));
    return exports;
}

void CreateNapiRetMsg(napi_env env, int32_t errorCode, napi_value* result, napi_value data)
{
    if (errorCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, DLP_OK, result));
        return;
    }

    std::string msg = GetErrStr(errorCode);
    DLP_LOG_DEBUG(LABEL, "message: %{public}s", msg.c_str());
    napi_value errInfoJs = nullptr;
    napi_value errorCodeJs = nullptr;
    napi_value errMsgJs = nullptr;

    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &errInfoJs));
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, errorCode, &errorCodeJs));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, errInfoJs, "code", errorCodeJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, errInfoJs, "data", errMsgJs));

    if (data != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, errInfoJs, "extra", data));
    }

    result[0] = errInfoJs;
}

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext* asyncContext, napi_value data)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value args[PARAM_SIZE_TWO] = {nullptr};
    CreateNapiRetMsg(env, asyncContext->errCode, &args[PARAM0], data);
    args[PARAM1] = data;
    if (asyncContext->deferred) {
        DLP_LOG_DEBUG(LABEL, "Promise");
        if (asyncContext->errCode == DLP_OK) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args[PARAM1]));
        } else {
            DLP_LOG_ERROR(LABEL, "Promise reject");
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, args[PARAM0]));
        }
    } else {
        DLP_LOG_DEBUG(LABEL, "Callback");
        napi_value callback = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        napi_value returnVal = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback, argc, &args[PARAM0], &returnVal));
    }
}

void GetGenerateDlpFileParams(
    const napi_env env, const napi_callback_info info, GenerateDlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plainTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get plain fd fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    if (!GetInt64Value(env, argv[PARAM1], asyncContext.cipherTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    if (!GetDlpProperty(env, argv[PARAM2], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }

    if (argc == PARAM_SIZE_FOUR) {
        GetCallback(env, argv[PARAM3], asyncContext);
    }

    DLP_LOG_DEBUG(LABEL,
        "Fd: %{private}ld, ownerAccount: %{private}s, ownerAccountType: %{private}d, contractAccount: %{private}s, "
        "size: "
        "%{private}zu",
        asyncContext.plainTxtFd, asyncContext.property.ownerAccount.c_str(), asyncContext.property.ownerAccountType,
        asyncContext.property.contractAccount.c_str(), asyncContext.property.authUsers.size());
}

void GetOpenDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.cipherTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }

    if (argc == PARAM_SIZE_TWO) {
        GetCallback(env, argv[PARAM1], asyncContext);
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}ld", asyncContext.cipherTxtFd);
}

void GetIsDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.cipherTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }

    if (argc == PARAM_SIZE_TWO) {
        GetCallback(env, argv[PARAM1], asyncContext);
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}ld", asyncContext.cipherTxtFd);
}

void GetDlpLinkFileParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        asyncContext.errCode = DLP_NAPI_ERROR_THIS_VALUE_NULL;
        return;
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)));
        if (asyncContext.dlpFileNative == nullptr) {
            DLP_LOG_ERROR(LABEL, "cannot get native object");
            asyncContext.errCode = DLP_NAPI_ERROR_UNWRAP_FAIL;
            return;
        }

        if (!GetStringValue(env, argv[PARAM0], asyncContext.linkFileName)) {
            DLP_LOG_ERROR(LABEL, "linkFileName is invalid");
            asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
            return;
        }

        if (argc == PARAM_SIZE_TWO) {
            GetCallback(env, argv[PARAM1], asyncContext);
        }
    }

    DLP_LOG_DEBUG(LABEL, "linkFileName: %{private}s", asyncContext.linkFileName.c_str());
}

void GetRecoverDlpFileParams(
    const napi_env env, const napi_callback_info info, RecoverDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        asyncContext.errCode = DLP_NAPI_ERROR_THIS_VALUE_NULL;
        return;
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)));
        if (asyncContext.dlpFileNative == nullptr) {
            DLP_LOG_ERROR(LABEL, "cannot get native object");
            asyncContext.errCode = DLP_NAPI_ERROR_UNWRAP_FAIL;
            return;
        }

        if (!GetInt64Value(env, argv[PARAM0], asyncContext.plainFd)) {
            DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
            asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
            return;
        }

        if (argc == PARAM_SIZE_TWO) {
            GetCallback(env, argv[PARAM1], asyncContext);
        }
    }

    DLP_LOG_DEBUG(LABEL, "plainFd: %{private}ld", asyncContext.plainFd);
}

void GetCloseDlpFileParams(const napi_env env, const napi_callback_info info, CloseDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        asyncContext.errCode = DLP_NAPI_ERROR_THIS_VALUE_NULL;
        return;
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)));
        if (asyncContext.dlpFileNative == nullptr) {
            DLP_LOG_ERROR(LABEL, "cannot get native object");
            asyncContext.errCode = DLP_NAPI_ERROR_UNWRAP_FAIL;
            return;
        }

        if (argc == PARAM_SIZE_ONE) {
            GetCallback(env, argv[PARAM0], asyncContext);
        }
    }
}

void GetInstallDlpSandboxParams(const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get perm fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    asyncContext.permType = static_cast<AuthPermType>(res);
    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    asyncContext.userId = static_cast<int32_t>(res);

    if (argc == PARAM_SIZE_FOUR) {
        GetCallback(env, argv[PARAM3], asyncContext);
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, permType: %{private}d, userId: %{private}d",
        asyncContext.bundleName.c_str(), asyncContext.permType, asyncContext.userId);
}

void GetUninstallDlpSandboxParams(
    const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }

    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    asyncContext.userId = static_cast<int32_t>(res);

    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get app index fail");
        asyncContext.errCode = DLP_NAPI_ERROR_PARSE_JS_PARAM;
        return;
    }
    asyncContext.appIndex = static_cast<int32_t>(res);

    if (argc == PARAM_SIZE_FOUR) {
        GetCallback(env, argv[PARAM3], asyncContext);
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, userId: %{private}d, appIndex: %{private}d",
        asyncContext.bundleName.c_str(), asyncContext.userId, asyncContext.appIndex);
}

void GetThirdInterfaceParams(
    const napi_env env, const napi_callback_info info, CommonAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc == PARAM_SIZE_ONE) {
        GetCallback(env, argv[PARAM0], asyncContext);
    }
}

bool GetDlpProperty(napi_env env, napi_value jsObject, DlpProperty& property)
{
    if (!GetStringValueByKey(env, jsObject, "ownerAccount", property.ownerAccount)) {
        DLP_LOG_ERROR(LABEL, "js get owner account fail");
        return false;
    }
    int64_t type;
    if (!GetInt64ValueByKey(env, jsObject, "ownerAccountType", type)) {
        DLP_LOG_ERROR(LABEL, "js get owner account type fail");
        return false;
    }
    property.ownerAccountType = static_cast<DlpAccountType>(type);
    if (!GetVectorAuthUserByKey(env, jsObject, "authUsers", property.authUsers)) {
        DLP_LOG_ERROR(LABEL, "js get auth users fail");
        return false;
    }
    if (!GetStringValueByKey(env, jsObject, "contractAccount", property.contractAccount)) {
        DLP_LOG_ERROR(LABEL, "js get contact account fail");
        return false;
    }
    DLP_LOG_DEBUG(LABEL,
        "ownerAccount: %{private}s, authUsers size: %{private}zu, contractAccount: %{private}s, ownerAccountType: "
        "%{private}d",
        property.ownerAccount.c_str(), property.authUsers.size(), property.contractAccount.c_str(),
        property.ownerAccountType);
    return true;
}

napi_value DlpPropertyToJs(napi_env env, const DlpProperty& property)
{
    napi_value dlpPropertyJs = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dlpPropertyJs));

    napi_value ownerAccountJs;
    NAPI_CALL(env, napi_create_string_utf8(env, property.ownerAccount.c_str(), NAPI_AUTO_LENGTH, &ownerAccountJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "ownerAccount", ownerAccountJs));

    napi_value vectorAuthUserJs = VectorAuthUserToJs(env, property.authUsers);
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "authUsers", vectorAuthUserJs));

    napi_value contractAccountJs;
    NAPI_CALL(
        env, napi_create_string_utf8(env, property.contractAccount.c_str(), NAPI_AUTO_LENGTH, &contractAccountJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "contractAccount", contractAccountJs));

    napi_value ownerAccountTypeJs;
    NAPI_CALL(env, napi_create_int64(env, property.ownerAccountType, &ownerAccountTypeJs));
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "ownerAccountType", ownerAccountTypeJs));

    return dlpPropertyJs;
}

napi_value VectorAuthUserToJs(napi_env env, const std::vector<AuthUserInfo>& users)
{
    napi_value vectorAuthUserJs = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &vectorAuthUserJs));
    for (auto item : users) {
        napi_value objAuthUserInfo = nullptr;
        NAPI_CALL(env, napi_create_object(env, &objAuthUserInfo));

        napi_value authAccountJs;
        NAPI_CALL(env, napi_create_string_utf8(env, item.authAccount.c_str(), NAPI_AUTO_LENGTH, &authAccountJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "authAccount", authAccountJs));

        napi_value authPermJs;
        NAPI_CALL(env, napi_create_int64(env, item.authPerm, &authPermJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "authPerm", authPermJs));

        napi_value permExpiryTimeJs;
        NAPI_CALL(env, napi_create_int64(env, item.permExpiryTime, &permExpiryTimeJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "permExpiryTime", permExpiryTimeJs));

        napi_value authAccountTypeJs;
        NAPI_CALL(env, napi_create_int64(env, item.authAccountType, &authAccountTypeJs));
        NAPI_CALL(env, napi_set_named_property(env, objAuthUserInfo, "authAccountType", authAccountTypeJs));

        NAPI_CALL(env, napi_set_element(env, vectorAuthUserJs, index, objAuthUserInfo));
        index++;
    }
    return vectorAuthUserJs;
}

napi_value VectorStringToJs(napi_env env, const std::vector<std::string>& value)
{
    napi_value jsArray = nullptr;
    uint32_t index = 0;
    NAPI_CALL(env, napi_create_array(env, &jsArray));
    for (const auto& iter : value) {
        napi_value jsValue = nullptr;
        if (napi_create_string_utf8(env, iter.c_str(), NAPI_AUTO_LENGTH, &jsValue) == napi_ok) {
            if (napi_set_element(env, jsArray, index, jsValue) == napi_ok) {
                index++;
            }
        }
    }
    return jsArray;
}

void GetCallback(const napi_env env, napi_value jsObject, CommonAsyncContext& asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_RETURN_VOID(env, napi_typeof(env, jsObject, &valueType));
    if (valueType == napi_function) {
        NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, 1, &asyncContext.callbackRef));
    } else {
        DLP_LOG_ERROR(LABEL, "get callback fail");
    }
}

napi_value GetNapiValue(napi_env env, napi_value jsObject, const std::string& key)
{
    if (jsObject == nullptr) {
        DLP_LOG_ERROR(LABEL, "Js object is nullptr");
        return nullptr;
    }
    napi_value keyValue;
    NAPI_CALL(env, napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &keyValue));
    bool result = false;
    NAPI_CALL(env, napi_has_property(env, jsObject, keyValue, &result));
    if (result) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_property(env, jsObject, keyValue, &value));
        return value;
    }
    DLP_LOG_ERROR(LABEL, "get napi value fail");
    return nullptr;
}

bool GetStringValue(napi_env env, napi_value jsObject, std::string& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_string) {
        DLP_LOG_ERROR(LABEL, "object is no a string");
        return false;
    }

    size_t size = 0;
    if (napi_get_value_string_utf8(env, jsObject, nullptr, 0, &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get string size");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, jsObject, result.data(), (size + 1), &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get string value");
        return false;
    }
    return true;
}

bool GetStringValueByKey(napi_env env, napi_value jsObject, const std::string& key, std::string& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetStringValue(env, value, result);
}

bool GetInt64Value(napi_env env, napi_value jsObject, int64_t& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_number) {
        DLP_LOG_ERROR(LABEL, "object is no a number");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_int64(env, jsObject, &result), false);
    return true;
}

bool GetInt64ValueByKey(napi_env env, napi_value jsObject, const std::string& key, int64_t& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetInt64Value(env, value, result);
}

bool GetUint32Value(napi_env env, napi_value jsObject, uint32_t& result)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, jsObject, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType != napi_number) {
        DLP_LOG_ERROR(LABEL, "object is no a number");
        return false;
    }
    NAPI_CALL_BASE(env, napi_get_value_uint32(env, jsObject, &result), false);
    return true;
}

bool GetUint32ValueByKey(napi_env env, napi_value jsObject, const std::string& key, uint32_t& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetUint32Value(env, value, result);
}

napi_value GetArrayValueByKey(napi_env env, napi_value jsObject, const std::string& key)
{
    napi_value array = GetNapiValue(env, jsObject, key);
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, array, &isArray));
    if (!isArray) {
        DLP_LOG_ERROR(LABEL, "value is not array");
        return nullptr;
    }
    return array;
}

bool GetVectorAuthUser(napi_env env, napi_value jsObject, std::vector<AuthUserInfo>& resultVec)
{
    uint32_t size = 0;
    if (napi_get_array_length(env, jsObject, &size) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "js get array size fail");
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        napi_value obj;
        NAPI_CALL_BASE(env, napi_get_element(env, jsObject, i, &obj), false);
        AuthUserInfo userInfo;
        if (!GetStringValueByKey(env, obj, "authAccount", userInfo.authAccount)) {
            DLP_LOG_ERROR(LABEL, "js get auth account fail");
            resultVec.clear();
            return false;
        }
        int64_t perm;
        if (!GetInt64ValueByKey(env, obj, "authPerm", perm)) {
            DLP_LOG_ERROR(LABEL, "js get auth perm fail");
            resultVec.clear();
            return false;
        }
        userInfo.authPerm = static_cast<AuthPermType>(perm);
        int64_t time;
        if (!GetInt64ValueByKey(env, obj, "permExpiryTime", time)) {
            DLP_LOG_ERROR(LABEL, "js get time fail");
            resultVec.clear();
            return false;
        }
        userInfo.permExpiryTime = static_cast<uint64_t>(time);
        int64_t type;
        if (!GetInt64ValueByKey(env, obj, "authAccountType", type)) {
            DLP_LOG_ERROR(LABEL, "js get type fail");
            resultVec.clear();
            return false;
        }
        userInfo.authAccountType = static_cast<DlpAccountType>(type);
        resultVec.push_back(userInfo);
    }
    return true;
}

bool GetVectorAuthUserByKey(
    napi_env env, napi_value jsObject, const std::string& key, std::vector<AuthUserInfo>& resultVec)
{
    napi_value userArray = GetArrayValueByKey(env, jsObject, key);
    if (userArray == nullptr) {
        DLP_LOG_ERROR(LABEL, "User array is null");
        return false;
    }
    return GetVectorAuthUser(env, userArray, resultVec);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
