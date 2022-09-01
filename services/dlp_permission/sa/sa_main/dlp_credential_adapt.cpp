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

#include "dlp_credential_adapt.h"
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include "dlp_credential_service.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCredential"};
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
static const size_t MAX_REQUEST_NUM = 100;
static std::unordered_map<uint64_t, sptr<IDlpPermissionCallback>> g_requestMap;
std::mutex g_lockRequest;
}  // namespace

static sptr<IDlpPermissionCallback> GetCallbackFromRequestMap(uint64_t requestId)
{
    DLP_LOG_INFO(LABEL, "Get callback, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    sptr<IDlpPermissionCallback> callback = nullptr;
    std::lock_guard<std::mutex> lock(g_lockRequest);
    auto iter = g_requestMap.find(requestId);
    if (iter != g_requestMap.end()) {
        callback = iter->second;
        g_requestMap.erase(requestId);
        return callback;
    }
    DLP_LOG_ERROR(LABEL, "Callback not found");
    return nullptr;
}

static int32_t InsertCallbackToRequestMap(uint64_t requestId, sptr<IDlpPermissionCallback>& callback)
{
    DLP_LOG_DEBUG(LABEL, "insert request, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    if (g_requestMap.count(requestId) > 0) {
        DLP_LOG_ERROR(LABEL, "Duplicate task, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE;
    }
    g_requestMap[requestId] = callback;
    return DLP_OK;
}

static int32_t QueryRequestIdle()
{
    DLP_LOG_DEBUG(LABEL, "Total tasks: %{public}zu", g_requestMap.size());
    if (g_requestMap.size() > MAX_REQUEST_NUM) {
        DLP_LOG_ERROR(LABEL, "Task busy");
        return DLP_SERVICE_ERROR_CREDENTIAL_BUSY;
    }
    return DLP_OK;
}

static void DlpPackPolicyCallback(uint64_t requestId, int errorCode, DLP_EncPolicyData* outParams)
{
    DLP_LOG_INFO(LABEL, "Called, requestId: %{public}llu", static_cast<unsigned long long>(requestId));

    auto callback = GetCallbackFromRequestMap(requestId);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "callback is null");
        return;
    }

    if (errorCode != 0) {
        DLP_LOG_ERROR(LABEL, "Pack Policy error, errorCode: %{public}d", errorCode);
        callback->onGenerateDlpCertificate(errorCode, std::vector<uint8_t>());
        return;
    }

    if (outParams == nullptr || outParams->data == nullptr || outParams->featureName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->onGenerateDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, std::vector<uint8_t>());
        return;
    }

    std::vector<uint8_t> cert(outParams->data, outParams->data + outParams->dataLen);
    callback->onGenerateDlpCertificate(errorCode, cert);
}

static void DlpRestorePolicyCallback(uint64_t requestId, int errorCode, DLP_RestorePolicyData* outParams)
{
    DLP_LOG_INFO(LABEL, "Called, requestId: %{public}llu", static_cast<unsigned long long>(requestId));

    auto callback = GetCallbackFromRequestMap(requestId);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "callback is null");
        return;
    }
    PermissionPolicy policyInfo;
    if (errorCode != 0) {
        DLP_LOG_ERROR(LABEL, "Restore Policy error, errorCode: %{public}d", errorCode);
        callback->onParseDlpCertificate(errorCode, policyInfo);
        return;
    }
    if (outParams == nullptr || outParams->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->onParseDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, policyInfo);
        return;
    }

    auto policyStr = new (std::nothrow) char[outParams->dataLen + 1];
    if (policyStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        callback->onParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo);
        return;
    }
    if (memcpy_s(policyStr, outParams->dataLen + 1, outParams->data, outParams->dataLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
        delete[] policyStr;
        callback->onParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo);
        return;
    }
    policyStr[outParams->dataLen] = '\0';

    auto jsonObj = nlohmann::json::parse(policyStr, policyStr + outParams->dataLen + 1, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        delete[] policyStr;
        callback->onParseDlpCertificate(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, policyInfo);
        return;
    }
    delete[] policyStr;
    policyStr = nullptr;
    int32_t res = DlpPermissionSerializer::GetInstance().DeserializeDlpPermission(jsonObj, policyInfo);
    if (res != DLP_OK) {
        callback->onParseDlpCertificate(res, policyInfo);
        return;
    }
    callback->onParseDlpCertificate(errorCode, policyInfo);
}

DlpCredential& DlpCredential::GetInstance()
{
    static DlpCredential instance;
    return instance;
}

static void FreeDlpPackPolicyParams(DLP_PackPolicyParams& packPolicy)
{
    if (packPolicy.featureName != nullptr) {
        free(packPolicy.featureName);
        packPolicy.featureName = nullptr;
    }
    if (packPolicy.data != nullptr) {
        free(packPolicy.data);
        packPolicy.data = nullptr;
    }
}

DlpCredential::DlpCredential()
{}

static int GetOsAccountIdFromUid(int uid)
{
    return uid / UID_TRANSFORM_DIVISOR;
}

int32_t DlpCredential::GenerateDlpCertificate(
    const std::string& policy, DlpAccountType accountType, sptr<IDlpPermissionCallback>& callback)
{
    DLP_PackPolicyParams packPolicy = {
        .featureName = strdup("dlp_permission_service"),
        .data = (uint8_t*)strdup(policy.c_str()),
        .dataLen = policy.size(),
        .accountType = static_cast<AccountType>(accountType),
    };

    int res = 0;
    {
        std::lock_guard<std::mutex> lock(g_lockRequest);
        int32_t status = QueryRequestIdle();
        if (status != DLP_OK) {
            FreeDlpPackPolicyParams(packPolicy);
            return status;
        }

        uint64_t requestId;
        res = DLP_PackPolicy(
            GetOsAccountIdFromUid(IPCSkeleton::GetCallingUid()), &packPolicy, DlpPackPolicyCallback, &requestId);
        if (res == 0) {
            DLP_LOG_INFO(
                LABEL, "Start request success, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
            res = InsertCallbackToRequestMap(requestId, callback);
            if (res != DLP_OK) {
                FreeDlpPackPolicyParams(packPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDlpPackPolicyParams(packPolicy);
    return res == 0 ? DLP_OK : DLP_SERVICE_ERROR_CREDENTIAL_OPERATE_FAIL;
}

static void FreeDLPEncPolicyData(DLP_EncPolicyData& encPolicy)
{
    if (encPolicy.featureName != nullptr) {
        free(encPolicy.featureName);
        encPolicy.featureName = nullptr;
    }
    if (encPolicy.data != nullptr) {
        delete[] encPolicy.data;
        encPolicy.data = nullptr;
    }
}

int32_t DlpCredential::ParseDlpCertificate(const std::vector<uint8_t>& cert, sptr<IDlpPermissionCallback>& callback)
{
    auto data = new (std::nothrow) uint8_t[cert.size()];
    if (data == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (memcpy_s(data, cert.size(), &cert[0], cert.size()) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
        delete[] data;
        data = nullptr;
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DLP_EncPolicyData encPolicy = {
        .featureName = strdup("dlp_permission_service"),
        .data = data,
        .dataLen = cert.size(),
    };
    int res = 0;
    {
        std::lock_guard<std::mutex> lock(g_lockRequest);
        int32_t status = QueryRequestIdle();
        if (status != DLP_OK) {
            FreeDLPEncPolicyData(encPolicy);
            return status;
        }

        uint64_t requestId;
        res = DLP_RestorePolicy(
            GetOsAccountIdFromUid(IPCSkeleton::GetCallingUid()), &encPolicy, DlpRestorePolicyCallback, &requestId);
        if (res == 0) {
            DLP_LOG_INFO(
                LABEL, "Start request success, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
            res = InsertCallbackToRequestMap(requestId, callback);
            if (res != DLP_OK) {
                FreeDLPEncPolicyData(encPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDLPEncPolicyData(encPolicy);
    return res == 0 ? DLP_OK : DLP_SERVICE_ERROR_CREDENTIAL_OPERATE_FAIL;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
