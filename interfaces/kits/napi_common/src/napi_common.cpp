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

#include "ability.h"
#include "ability_manager_client.h"
#include "napi_common.h"
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "napi_base_context.h"
#include "napi_error_msg.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"};
}  // namespace

napi_value GenerateBusinessError(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    napi_value errCodeJs = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, jsErrCode, &errCodeJs));

    napi_value errMsgJs = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, jsErrMsg.c_str(), NAPI_AUTO_LENGTH, &errMsgJs));

    napi_value errJs = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, errMsgJs, &errJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "code", errCodeJs));
    NAPI_CALL(env, napi_set_named_property(env, errJs, "message", errMsgJs));
    return errJs;
}

void DlpNapiThrow(napi_env env, int32_t nativeErrCode)
{
    int32_t jsErrCode = NativeCodeToJsCode(nativeErrCode);
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode))));
}

void DlpNapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg)
{
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, jsErrCode, jsErrMsg)));
}

static void ThrowParamError(const napi_env env, const std::string& param, const std::string& type)
{
    std::string msg = "Parameter Error. The type of \"" + param + "\" must be " + type + ".";
    DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, msg);
}

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

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext* asyncContext, napi_value data)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value args[PARAM_SIZE_TWO] = {nullptr};

    if (asyncContext->errCode == DLP_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[PARAM0]));
        args[PARAM1] = data;
    } else {
        int32_t jsErrCode = NativeCodeToJsCode(asyncContext->errCode);
        napi_value errObj = GenerateBusinessError(env, jsErrCode, GetJsErrMsg(jsErrCode));
        if (data != nullptr) {
            NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, errObj, "extra", data));
        }
        args[PARAM0] = errObj;
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &args[PARAM1]));
    }

    if (asyncContext->deferred) {
        DLP_LOG_DEBUG(LABEL, "Promise");
        if (asyncContext->errCode == DLP_OK) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, args[PARAM1]));
        } else {
            DLP_LOG_ERROR(LABEL, "Promise reject, errCode=%{public}d", asyncContext->errCode);
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

static bool NapiCheckArgc(const napi_env env, int32_t argc, int32_t reqSize)
{
    if (argc < (reqSize - 1)) {
        DLP_LOG_ERROR(LABEL, "params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need at least " + std::to_string(reqSize - 1) +
            ", given " + std::to_string(argc);
        DlpNapiThrow(env, ERR_JS_PARAMETER_ERROR, errMsg);
        return false;
    }
    return true;
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static napi_value GetAbilityContext(const napi_env &env, const napi_value &value,
    std::shared_ptr<AbilityRuntime::AbilityContext> &abilityContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        DLP_LOG_ERROR(LABEL, "it is not a stage mode");
        return nullptr;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            DLP_LOG_ERROR(LABEL, "get context failed");
            return nullptr;
        }
        abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (abilityContext == nullptr) {
            DLP_LOG_ERROR(LABEL, "get Stage model ability context failed");
            return nullptr;
        }
        return WrapVoidToJS(env);
    }
}

static bool GetDstFileInfo(const napi_env &env, const napi_value &value, GenerateDlpFileAsyncContext& asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, value, &valueType) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }
    if (valueType == napi_string) {
        if (!GetStringValue(env, value, asyncContext.fileName)) {
            DLP_LOG_ERROR(LABEL, "js get fileName fail");
            ThrowParamError(env, "fileName", "string");
            return false;
        }
    } else {
        if (!GetInt64Value(env, value, asyncContext.cipherTextFd)) {
            DLP_LOG_ERROR(LABEL, "js get cipherTextFd fail");
            ThrowParamError(env, "cipherTextFd", "number");
            return false;
        }
    }
    return true;
}

bool GetGenerateDlpFileParams(
    const napi_env env, const napi_callback_info info, GenerateDlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FIVE;
    napi_value argv[PARAM_SIZE_FIVE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FIVE)) {
        return false;
    }

    if (GetAbilityContext(env, argv[PARAM0], asyncContext.abilityContext) == nullptr) {
        DLP_LOG_ERROR(LABEL, "js get abilityContext fail");
        ThrowParamError(env, "plainTxtFd", "number");
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM1], asyncContext.plainTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get plain fd fail");
        ThrowParamError(env, "plainTxtFd", "number");
        return false;
    }

    if (!GetDstFileInfo(env, argv[PARAM2], asyncContext)) {
        return false;
    }

    if (!GetDlpProperty(env, argv[PARAM3], asyncContext.property)) {
        DLP_LOG_ERROR(LABEL, "js get property fail");
        ThrowParamError(env, "property", "DlpProperty");
        return false;
    }

    if (argc == PARAM_SIZE_FIVE) {
        if (!GetCallback(env, argv[PARAM4], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL,
        "Fd: %{private}ld, ownerAccount: %{private}s, ownerAccountType: %{private}d, contractAccount: %{private}s, "
        "size: "
        "%{private}zu",
        asyncContext.plainTxtFd, asyncContext.property.ownerAccount.c_str(), asyncContext.property.ownerAccountType,
        asyncContext.property.contractAccount.c_str(), asyncContext.property.authUsers.size());
    return true;
}

bool GetOpenDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.cipherTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "cipherTxtFd", "number");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!GetCallback(env, argv[PARAM1], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}ld", asyncContext.cipherTxtFd);
    return true;
}

bool GetIsDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.cipherTxtFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "cipherTxtFd", "number");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!GetCallback(env, argv[PARAM1], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "Fd: %{private}ld", asyncContext.cipherTxtFd);
    return true;
}

bool GetDlpLinkFileParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.linkFileName)) {
        DLP_LOG_ERROR(LABEL, "linkFileName is invalid");
        ThrowParamError(env, "linkFileName", "string");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!GetCallback(env, argv[PARAM1], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "linkFileName: %{private}s", asyncContext.linkFileName.c_str());
    return true;
}

bool GetRecoverDlpFileParams(
    const napi_env env, const napi_callback_info info, RecoverDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_TWO)) {
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (!GetInt64Value(env, argv[PARAM0], asyncContext.plainFd)) {
        DLP_LOG_ERROR(LABEL, "js get cipher fd fail");
        ThrowParamError(env, "plainFd", "number");
        return false;
    }

    if (argc == PARAM_SIZE_TWO) {
        if (!GetCallback(env, argv[PARAM1], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "plainFd: %{private}ld", asyncContext.plainFd);
    return true;
}

bool GetCloseDlpFileParams(const napi_env env, const napi_callback_info info, CloseDlpFileAsyncContext& asyncContext)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        DLP_LOG_ERROR(LABEL, "This var is null");
        return false;
    }

    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext.dlpFileNative)), false);
    if (asyncContext.dlpFileNative == nullptr) {
        DLP_LOG_ERROR(LABEL, "cannot get native object");
        return false;
    }

    if (argc == PARAM_SIZE_ONE) {
        if (!GetCallback(env, argv[PARAM0], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    return true;
}

bool GetInstallDlpSandboxParams(const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        ThrowParamError(env, "bundleName", "string");
        return false;
    }
    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get perm fail");
        ThrowParamError(env, "permType", "number");
        return false;
    }
    asyncContext.permType = static_cast<AuthPermType>(res);
    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        ThrowParamError(env, "userId", "number");
        return false;
    }
    asyncContext.userId = static_cast<int32_t>(res);

    if (argc == PARAM_SIZE_FOUR) {
        if (!GetCallback(env, argv[PARAM3], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, permType: %{private}d, userId: %{private}d",
        asyncContext.bundleName.c_str(), asyncContext.permType, asyncContext.userId);
    return true;
}

bool GetUninstallDlpSandboxParams(
    const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_FOUR;
    napi_value argv[PARAM_SIZE_FOUR] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (!NapiCheckArgc(env, argc, PARAM_SIZE_FOUR)) {
        return false;
    }

    if (!GetStringValue(env, argv[PARAM0], asyncContext.bundleName)) {
        DLP_LOG_ERROR(LABEL, "js get bundle name fail");
        ThrowParamError(env, "bundleName", "string");
        return false;
    }

    int64_t res;
    if (!GetInt64Value(env, argv[PARAM1], res)) {
        DLP_LOG_ERROR(LABEL, "js get user id fail");
        ThrowParamError(env, "userId", "number");
        return false;
    }
    asyncContext.userId = static_cast<int32_t>(res);

    if (!GetInt64Value(env, argv[PARAM2], res)) {
        DLP_LOG_ERROR(LABEL, "js get app index fail");
        ThrowParamError(env, "appIndex", "number");
        return false;
    }
    asyncContext.appIndex = static_cast<int32_t>(res);

    if (argc == PARAM_SIZE_FOUR) {
        if (!GetCallback(env, argv[PARAM3], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }

    DLP_LOG_DEBUG(LABEL, "bundleName: %{private}s, userId: %{private}d, appIndex: %{private}d",
        asyncContext.bundleName.c_str(), asyncContext.userId, asyncContext.appIndex);
    return true;
}

bool GetThirdInterfaceParams(
    const napi_env env, const napi_callback_info info, CommonAsyncContext& asyncContext)
{
    size_t argc = PARAM_SIZE_ONE;
    napi_value argv[PARAM_SIZE_ONE] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);

    if (argc == PARAM_SIZE_ONE) {
        if (!GetCallback(env, argv[PARAM0], asyncContext)) {
            ThrowParamError(env, "callback", "function");
            return false;
        }
    }
    return true;
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
    if(!GetBoolValueByKey(env, jsObject, "offlineAccess", property.offlineAccess)) {
        DLP_LOG_ERROR(LABEL, "js get offline access flag fail");
        return false;
    }

    DLP_LOG_DEBUG(LABEL,
        "ownerAccount: %{private}s, authUsers size: %{private}zu, contractAccount: %{private}s, ownerAccountType: "
        "%{private}d, offlineAccess: %{private}d",
        property.ownerAccount.c_str(), property.authUsers.size(), property.contractAccount.c_str(),
        property.ownerAccountType, property.offlineAccess);
    return true;
}

napi_value DlpPropertyToJs(napi_env env, const DlpProperty& property)
{
    napi_value dlpPropertyJs = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dlpPropertyJs));

    napi_value offlineAccessJs;
    napi_get_boolean(env, property.offlineAccess, &offlineAccessJs);
    NAPI_CALL(env, napi_set_named_property(env, dlpPropertyJs, "offlineAccess", offlineAccessJs));

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

bool GetCallback(const napi_env env, napi_value jsObject, CommonAsyncContext& asyncContext)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsObject, &valueType), false);
    if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, jsObject, 1, &asyncContext.callbackRef), false);
        return true;
    } else {
        DLP_LOG_ERROR(LABEL, "get callback fail");
        return false;
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

bool GetBoolValue(napi_env env, napi_value jsObject, bool& result)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, jsObject, &valuetype) != napi_ok) {
        DLP_LOG_ERROR(LABEL, "Can not get napi type");
        return false;
    }

    if (valuetype != napi_boolean) {
        DLP_LOG_ERROR(LABEL, "Wrong argument type. Boolean expected.");
        return false;
    }

    napi_get_value_bool(env, jsObject, &result);
    return true;
}

bool GetBoolValueByKey(napi_env env, napi_value jsObject, const std::string& key, bool& result)
{
    napi_value value = GetNapiValue(env, jsObject, key);
    return GetBoolValue(env, value, result);
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
