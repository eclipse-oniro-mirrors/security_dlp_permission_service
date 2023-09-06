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

#include "dlp_credential_adapt.h"
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include "account_adapt.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
const std::string LOCAL_ENCRYPTED_CERT = "encryptedPolicy";
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCredential"};
static const size_t MAX_REQUEST_NUM = 100;
static std::unordered_map<uint64_t, sptr<IDlpPermissionCallback>> g_requestMap;
static std::unordered_map<uint64_t, DlpAccountType> g_requestAccountTypeMap;
std::mutex g_lockRequest;
}  // namespace

static bool IsDlpCredentialHuksError(int errorCode)
{
    return ((errorCode >= DLP_ERR_GENERATE_KEY_FAILED) && (errorCode < DLP_ERR_IPC_INTERNAL_FAILED));
}

static bool IsDlpCredentialIpcError(int errorCode)
{
    return ((errorCode >= DLP_ERR_IPC_INTERNAL_FAILED) && (errorCode < DLP_ERR_CONNECTION_TIME_OUT));
}

static bool IsDlpCredentialServerError(int errorCode)
{
    return ((errorCode >= DLP_ERR_CONNECTION_TIME_OUT) && (errorCode < DLP_ERR_FILE_PATH));
}

static bool IsNoPermissionError(int errorCode)
{
    return ((errorCode == DLP_ERR_CONNECTION_VIP_RIGHT_EXPIRED) || (errorCode == DLP_ERR_CONNECTION_NO_PERMISSION) ||
            (errorCode == DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED));
}

static bool IsNoAccountError(int errorCode)
{
    return ((errorCode == DLP_ERR_CREDENTIAL_NOT_EXIST) || (errorCode == DLP_ERR_ACCOUNT_NOT_LOG_IN));
}

static int32_t ConvertCredentialError(int errorCode)
{
    if (errorCode == DLP_SUCCESS) {
        return DLP_OK;
    }
    if (errorCode == DLP_ERR_CONNECTION_TIME_OUT || errorCode == DLP_ERR_TOKEN_CONNECTION_TIME_OUT) {
        return DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR;
    }
    if (IsNoPermissionError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR;
    }
    if (IsNoAccountError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR;
    }
    if (IsDlpCredentialHuksError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_HUKS_ERROR;
    }
    if (IsDlpCredentialIpcError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_IPC_ERROR;
    }
    if (errorCode == DLP_ERR_TOKEN_CONNECTION_FAIL || IsDlpCredentialServerError(errorCode)) {
        return DLP_CREDENTIAL_ERROR_SERVER_ERROR;
    }
    return DLP_CREDENTIAL_ERROR_COMMON_ERROR;
}

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

static int32_t InsertCallbackToRequestMap(uint64_t requestId, const sptr<IDlpPermissionCallback>& callback)
{
    DLP_LOG_DEBUG(LABEL, "insert request, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    if (g_requestMap.count(requestId) > 0) {
        DLP_LOG_ERROR(LABEL, "Duplicate task, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE;
    }
    g_requestMap[requestId] = callback;
    return DLP_OK;
}

static DlpAccountType GetAccountTypeFromRequestMap(uint64_t requestId)
{
    DLP_LOG_INFO(LABEL, "Get callback, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    DlpAccountType accountType = INVALID_ACCOUNT;
    std::lock_guard<std::mutex> lock(g_lockRequest);
    auto iter = g_requestAccountTypeMap.find(requestId);
    if (iter != g_requestAccountTypeMap.end()) {
        accountType = iter->second;
        g_requestAccountTypeMap.erase(requestId);
        return accountType;
    }
    DLP_LOG_ERROR(LABEL, "Callback not found");
    return INVALID_ACCOUNT;
}

static int32_t InsertAccountTypeToRequestMap(uint64_t requestId, const DlpAccountType& accountType)
{
    DLP_LOG_DEBUG(LABEL, "insert request, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    if (g_requestAccountTypeMap.count(requestId) > 0) {
        DLP_LOG_ERROR(LABEL, "Duplicate task, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_DUPLICATE;
    }
    g_requestAccountTypeMap[requestId] = accountType;
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
        callback->OnGenerateDlpCertificate(ConvertCredentialError(errorCode), std::vector<uint8_t>());
        return;
    }

    if (outParams == nullptr || outParams->data == nullptr || outParams->featureName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->OnGenerateDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, std::vector<uint8_t>());
        return;
    }
    unordered_json encDataJson;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(*outParams, encDataJson);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Serialize fail");
        return;
    }
    std::string encData = encDataJson.dump();
    std::vector<uint8_t> cert(encData.begin(), encData.end());
    callback->OnGenerateDlpCertificate(errorCode, cert);
}

static std::vector<uint8_t> GetOfflineCert(const unordered_json& jsonObj)
{
    unordered_json encPolicyJson;
    if (jsonObj.find(LOCAL_ENCRYPTED_CERT) != jsonObj.end() && jsonObj.at(LOCAL_ENCRYPTED_CERT).is_object()) {
        jsonObj.at(LOCAL_ENCRYPTED_CERT).get_to(encPolicyJson);
    }

    std::string offPolicy = encPolicyJson.dump();
    std::vector<uint8_t> cert(offPolicy.begin(), offPolicy.end());
    return cert;
}

static void DlpRestorePolicyCallback(uint64_t requestId, int errorCode, DLP_RestorePolicyData* outParams)
{
    DLP_LOG_INFO(LABEL, "Called, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
    auto callback = GetCallbackFromRequestMap(requestId);
    auto accountType = GetAccountTypeFromRequestMap(requestId);
    if (callback == nullptr || accountType == INVALID_ACCOUNT) {
        DLP_LOG_ERROR(LABEL, "callback is null or accountType is 0");
        return;
    }
    PermissionPolicy policyInfo;
    if (errorCode != 0) {
        DLP_LOG_ERROR(LABEL, "Restore Policy error, errorCode: %{public}d", errorCode);
        callback->OnParseDlpCertificate(ConvertCredentialError(errorCode), policyInfo, {});
        return;
    }
    if (outParams == nullptr || outParams->data == nullptr) {
        DLP_LOG_ERROR(LABEL, "Params is null");
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_VALUE_INVALID, policyInfo, {});
        return;
    }
    auto policyStr = new (std::nothrow) char[outParams->dataLen + 1];
    if (policyStr == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo, {});
        return;
    }
    if (memcpy_s(policyStr, outParams->dataLen + 1, outParams->data, outParams->dataLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
        delete[] policyStr;
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, policyInfo, {});
        return;
    }
    policyStr[outParams->dataLen] = '\0';
    auto jsonObj = unordered_json::parse(policyStr, policyStr + outParams->dataLen + 1, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        delete[] policyStr;
        callback->OnParseDlpCertificate(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, policyInfo, {});
        return;
    }
    delete[] policyStr;
    policyStr = nullptr;
    int32_t res = DlpPermissionSerializer::GetInstance().DeserializeDlpPermission(jsonObj, policyInfo);
    if (res != DLP_OK) {
        callback->OnParseDlpCertificate(res, policyInfo, {});
        return;
    }
    policyInfo.ownerAccountType_ = accountType;
    callback->OnParseDlpCertificate(errorCode, policyInfo, GetOfflineCert(jsonObj));
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
    if (packPolicy.senderAccountInfo.accountId != nullptr) {
        free(packPolicy.senderAccountInfo.accountId);
        packPolicy.senderAccountInfo.accountId = nullptr;
    }
}

DlpCredential::DlpCredential()
{}

int32_t DlpCredential::GenerateDlpCertificate(
    const std::string& policy, const std::string& accountInfo,
    DlpAccountType accountType, sptr<IDlpPermissionCallback>& callback)
{
    EncAndDecOptions encAndDecOptions = {
        .opt = RECEIVER_DECRYPT_MUST_USE_CLOUD,
        .extraInfo = nullptr,
        .extraInfoLen = 0
    };

    AccountInfo accountCfg = {
        .accountId = reinterpret_cast<uint8_t*>(strdup(accountInfo.c_str())),
        .accountIdLen = accountInfo.size(),
    };

    DLP_PackPolicyParams packPolicy = {
        .featureName = strdup("dlp_permission_service"),
        .data = reinterpret_cast<uint8_t*>(strdup(policy.c_str())),
        .dataLen = policy.size(),
        .options = encAndDecOptions,
        .accountType = static_cast<AccountType>(accountType),
        .senderAccountInfo = accountCfg,
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
        res = DLP_PackPolicy(GetCallingUserId(), &packPolicy, DlpPackPolicyCallback, &requestId);
        if (res == 0) {
            DLP_LOG_INFO(
                LABEL, "Start request success, requestId: %{public}llu", static_cast<unsigned long long>(requestId));
            res = InsertCallbackToRequestMap(requestId, callback);
            if (res != DLP_OK) {
                FreeDlpPackPolicyParams(packPolicy);
                return res;
            }
            res = InsertAccountTypeToRequestMap(requestId, accountType);
            if (res != DLP_OK) {
                FreeDlpPackPolicyParams(packPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDlpPackPolicyParams(packPolicy);
    return ConvertCredentialError(res);
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
    if (encPolicy.options.extraInfo != nullptr) {
        delete[] encPolicy.options.extraInfo;
        encPolicy.options.extraInfo = nullptr;
    }
    if (encPolicy.receiverAccountInfo.accountId != nullptr) {
        free(encPolicy.receiverAccountInfo.accountId);
        encPolicy.receiverAccountInfo.accountId = nullptr;
    }
}

static CloudEncOption getCertOption(uint32_t flag)
{
    enum DlpAuthType opFlag = static_cast<enum DlpAuthType>(flag);

    switch (opFlag) {
        case DlpAuthType::ONLINE_AUTH_FOR_OFFLINE_CERT:
            return CloudEncOption::RECEIVER_DECRYPT_MUST_USE_CLOUD_AND_RETURN_ENCRYPTION_VALUE;
        case DlpAuthType::OFFLINE_AUTH_ONLY:
            return CloudEncOption::ALLOW_RECEIVER_DECRYPT_WITHOUT_USE_CLOUD;
        default:
            return CloudEncOption::RECEIVER_DECRYPT_MUST_USE_CLOUD;
    }
}

static int32_t GetLocalAccountName(std::string& account)
{
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (accountInfo.first) {
        account = accountInfo.second.name_;
        return DLP_OK;
    }
    return DLP_PARSE_ERROR_ACCOUNT_INVALID;
}

static int32_t GetDomainAccountName(std::string& account)
{
    std::vector<int32_t> ids;
    if (OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids) != 0) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    if (ids.size() != 1) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds size not 1");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    int32_t userId = ids[0];
    AccountSA::OsAccountInfo osAccountInfo;
    if (OHOS::AccountSA::OsAccountManager::QueryOsAccountById(userId, osAccountInfo) != 0) {
        DLP_LOG_ERROR(LABEL, "GetOsAccountLocalIdFromDomain return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    AccountSA::DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        DLP_LOG_ERROR(LABEL, "accountName_ empty");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    account = domainInfo.accountName_;
    return DLP_OK;
}

static void GetAccoutInfo(DlpAccountType accountType, AccountInfo& accountCfg)
{
    std::string account;
    if (accountType == DOMAIN_ACCOUNT) {
        if (GetDomainAccountName(account) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "query GetDomainAccountName failed");
            return;
        }
    } else {
        if (GetLocalAccountName(account) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "query GetLocalAccountName failed");
            return;
        }
    }

    accountCfg = {
        .accountId = reinterpret_cast<uint8_t*>(strdup(account.c_str())),
        .accountIdLen = account.size(),
    };
}

int32_t DlpCredential::ParseDlpCertificate(const std::vector<uint8_t>& cert, uint32_t flag,
    sptr<IDlpPermissionCallback>& callback)
{
    std::string encDataJsonStr(cert.begin(), cert.end());
    auto jsonObj = unordered_json::parse(encDataJsonStr, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    EncAndDecOptions encAndDecOptions = {
        .opt = getCertOption(flag)
    };
    DLP_EncPolicyData encPolicy = {
        .featureName = strdup("dlp_permission_service"),
        .options = encAndDecOptions,
    };
    bool opFlag = (encAndDecOptions.opt == CloudEncOption::ALLOW_RECEIVER_DECRYPT_WITHOUT_USE_CLOUD);
    int32_t result = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(jsonObj, encPolicy, opFlag);
    auto accountType = static_cast<DlpAccountType>(encPolicy.accountType);
    if (result != DLP_OK) {
        FreeDLPEncPolicyData(encPolicy);
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }

    GetAccoutInfo(accountType, encPolicy.receiverAccountInfo);

    int res = 0;
    {
        std::lock_guard<std::mutex> lock(g_lockRequest);
        int32_t status = QueryRequestIdle();
        if (status != DLP_OK) {
            FreeDLPEncPolicyData(encPolicy);
            return status;
        }
        uint64_t requestId;
        res = DLP_RestorePolicy(GetCallingUserId(), &encPolicy, DlpRestorePolicyCallback, &requestId);
        if (res == 0) {
            res = InsertCallbackToRequestMap(requestId, callback);
            int accountTypeRes = InsertAccountTypeToRequestMap(requestId, accountType);
            if (res != DLP_OK || accountTypeRes != DLP_OK) {
                FreeDLPEncPolicyData(encPolicy);
                return res;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "Start request fail, error: %{public}d", res);
        }
    }
    FreeDLPEncPolicyData(encPolicy);
    return ConvertCredentialError(res);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
