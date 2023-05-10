/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sandbox_json_manager.h"

#include <algorithm>
#include <iterator>
#include "appexecfwk_errors.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "i_json_operator.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using Json = nlohmann::json;
using namespace OHOS;
namespace {
const std::string APPINDEX = "appIndex";
const std::string BUNDLENAME = "bundleName";
const std::string DOCURISET = "docUriSet";
const std::string USERID = "userId";
const std::string TOKENID = "tokenId";
static const uint32_t MAX_RETENTION_SIZE = 1024;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "SandboxJsonManager" };
}

SandboxJsonManager::SandboxJsonManager()
{
    GetBundleMgr();
    infoVec_.clear();
}

SandboxJsonManager::~SandboxJsonManager()
{
    infoVec_.clear();
}

bool SandboxJsonManager::HasRetentionSandboxInfo(const std::string& bundleName)
{
    int32_t userId;
    if (!GetUserIdByActiveAccount(userId)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->bundleName == bundleName && iter->userId == userId) {
            return true;
        }
    }
    return false;
}

int32_t SandboxJsonManager::AddSandboxInfo(const int32_t& appIndex, const uint32_t& tokenId,
    const std::string& bundleName, const int32_t& userId)
{
    std::set<std::string> docUriSet;
    if (InsertSandboxInfo(docUriSet, tokenId, bundleName, appIndex, userId)) {
        return DLP_OK;
    }
    return DLP_RETENTION_INSERT_FILE_ERROR;
}

bool SandboxJsonManager::CanUninstall(const uint32_t& tokenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == tokenId) {
            if (iter->docUriSet.empty()) {
                return true;
            }
            return false;
        }
    }
    return true;
}

int32_t SandboxJsonManager::DelSandboxInfo(const uint32_t& tokenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == tokenId) {
            if (iter->docUriSet.empty()) {
                infoVec_.erase(iter);
                return DLP_OK;
            }
            DLP_LOG_ERROR(LABEL, "docUriset not empty tokenId:%{public}d", tokenId);
            return DLP_RETENTION_SERVICE_ERROR;
        }
    }
    DLP_LOG_ERROR(LABEL, "docUri not exist tokenId:%{public}d", tokenId);
    return DLP_RETENTION_SERVICE_ERROR;
}

int32_t SandboxJsonManager::UpdateRetentionState(const std::set<std::string>& docUriSet, RetentionInfo& info,
    bool isRetention)
{
    if (docUriSet.empty()) {
        return DLP_OK;
    }
    if (isRetention) {
        if (info.tokenId == 0) {
            DLP_LOG_ERROR(LABEL, "tokenId==0");
            return DLP_RETENTION_UPDATE_ERROR;
        }
        return UpdateRetentionState(docUriSet, info, CompareByTokenId, UpdateDocUriSetByUnion);
    }
    if (info.bundleName.empty() && info.tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "tokenId==0 and bundleName empty");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    GetUserIdByUid(info.userId);
    if (info.tokenId == 0) {
        return UpdateRetentionState(docUriSet, info, CompareByBundleName, UpdateDocUriSetByDifference);
    }
    return UpdateRetentionState(docUriSet, info, CompareByTokenId, UpdateDocUriSetByDifference);
}

bool SandboxJsonManager::CompareByTokenId(const RetentionInfo& info1, const RetentionInfo& info2)
{
    return info1.tokenId == info2.tokenId;
}

bool SandboxJsonManager::CompareByBundleName(const RetentionInfo& info1, const RetentionInfo& info2)
{
    return info1.bundleName == info2.bundleName && info1.userId == info2.userId;
}

bool SandboxJsonManager::UpdateDocUriSetByUnion(RetentionInfo& info, const std::set<std::string>& newSet)
{
    std::set<std::string> temp;
    std::set_union(info.docUriSet.begin(), info.docUriSet.end(), newSet.begin(), newSet.end(),
        std::insert_iterator<std::set<std::string>>(temp, temp.begin()));
    if (temp.size() > MAX_RETENTION_SIZE) {
        DLP_LOG_ERROR(LABEL, "size bigger than MAX_RETENTION_SIZE");
        return false;
    }
    bool isUpdate = info.docUriSet.size() != temp.size();
    info.docUriSet = temp;
    return isUpdate;
}

bool SandboxJsonManager::UpdateDocUriSetByDifference(RetentionInfo& info, const std::set<std::string>& newSet)
{
    if (info.docUriSet.empty()) {
        DLP_LOG_INFO(LABEL, "docUriSet size=0 ");
        return false;
    }
    std::set<std::string> temp;
    std::set_difference(info.docUriSet.begin(), info.docUriSet.end(), newSet.begin(), newSet.end(),
        std::insert_iterator<std::set<std::string>>(temp, temp.begin()));
    bool isUpdate = info.docUriSet.size() != temp.size();
    info.docUriSet = temp;
    return isUpdate;
}

int32_t SandboxJsonManager::UpdateRetentionState(const std::set<std::string>& newSet, const RetentionInfo& info,
    bool (*compare)(const RetentionInfo& info1, const RetentionInfo& info2),
    bool (*update)(RetentionInfo& info, const std::set<std::string>& newSet))
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool isUpdate = false;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (!compare(*iter, info)) {
            continue;
        }
        if (update(*iter, newSet)) {
            isUpdate = true;
        }
    }
    if (!isUpdate) {
        DLP_LOG_ERROR(LABEL, "not update : %{public}s", info.bundleName.c_str());
        return DLP_RETENTION_NOT_UPDATE;
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex)
{
    bool hasBundleName = false;
    {
        int32_t userId;
        if (!GetUserIdByActiveAccount(userId)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
            if (iter->bundleName == bundleName && iter->userId == userId) {
                if (appIndex != -1 && iter->appIndex != appIndex) {
                    ++iter;
                    continue;
                }
                iter = infoVec_.erase(iter);
                hasBundleName = true;
            } else {
                ++iter;
            }
        }
    }

    if (!hasBundleName) {
        DLP_LOG_ERROR(LABEL, "failed to find bundleName : %{public}s", bundleName.c_str());
        return DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention)
{
    if (infoVec_.empty()) {
        return DLP_OK;
    }

    int32_t userId;
    if (!GetUserIdByUid(userId)) {
        return DLP_RETENTION_SERVICE_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->bundleName != bundleName || iter->userId != userId) {
            continue;
        }
        if (isRetention && iter->docUriSet.empty()) {
            continue;
        }
        if (!isRetention && !iter->docUriSet.empty()) {
            continue;
        }
        RetentionSandBoxInfo info;
        info.bundleName_ = bundleName;
        info.appIndex_ = iter->appIndex;
        info.docUriSet_ = iter->docUriSet;
        retentionSandBoxInfoVec.push_back(info);
    }
    return DLP_OK;
}

int32_t SandboxJsonManager::ClearUnreservedSandbox()
{
    DLP_LOG_INFO(LABEL, "ClearUnreservedSandbox called");
    int32_t userId;
    if (!GetUserIdByActiveAccount(userId)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool isChanged = false;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
        if (!iter->docUriSet.empty() || iter->userId != userId) {
            ++iter;
            continue;
        }
        iter = infoVec_.erase(iter);
        isChanged = true;
    }
    if (!isChanged) {
        DLP_LOG_INFO(LABEL, "do not need update");
        return DLP_RETENTION_NOT_UPDATE;
    }
    return DLP_OK;
}

bool SandboxJsonManager::GetUserIdByUid(int32_t& userId)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    return GetUserIdFromUid(uid, &userId) == 0;
}

bool SandboxJsonManager::GetUserIdByActiveAccount(int32_t& userId)
{
    std::vector<int32_t> ids;
    if (OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids) != 0) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds return not 0");
        return false;
    }
    if (ids.size() != 1) {
        DLP_LOG_ERROR(LABEL, "QueryActiveOsAccountIds size not 1");
        return false;
    }
    userId = ids[0];
    return true;
}

int32_t SandboxJsonManager::ClearDateByUninstall()
{
    int32_t userId;
    if (!GetUserIdByActiveAccount(userId)) {
        return DLP_RETENTION_UPDATE_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool isNeedUpdate = false;
    std::map<std::string, bool> bundleInfoMap;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end();) {
        if (iter->userId == userId && (NeedRemove(*iter, userId, bundleInfoMap) || CheckReInstall(*iter, userId))) {
            iter = infoVec_.erase(iter);
            isNeedUpdate = true;
        } else {
            ++iter;
        }
    }
    if (!isNeedUpdate) {
        DLP_LOG_INFO(LABEL, "do not need update");
        return DLP_RETENTION_NOT_UPDATE;
    }
    return DLP_OK;
}

bool SandboxJsonManager::CheckReInstall(const RetentionInfo& info, const int32_t userId)
{
    uint32_t tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, info.bundleName, info.appIndex);
    if (tokenId == info.tokenId) {
        return false;
    }
    DLP_LOG_ERROR(LABEL, "GetHapTokenID not equal %{public}s,%{public}d", info.bundleName.c_str(), info.appIndex);
    return true;
}

bool SandboxJsonManager::NeedRemove(const RetentionInfo& info, int32_t userId,
    std::map<std::string, bool> bundleInfoMap)
{
    auto iter = bundleInfoMap.find(info.bundleName);
    if (iter != bundleInfoMap.end()) {
        return iter->second;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t res =
        bundleMgr_->GetBundleInfoV9(info.bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (res == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
        bundleInfoMap[info.bundleName] = true;
        return true;
    }
    DLP_LOG_ERROR(LABEL, "GetBundleInfo failed %{public}s,%{public}d", info.bundleName.c_str(), res);
    bundleInfoMap[info.bundleName] = false;
    return false;
}

sptr<AppExecFwk::IBundleMgr> SandboxJsonManager::GetBundleMgr()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex_);
        if (bundleMgr_ == nullptr) {
            auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (systemAbilityManager == nullptr) {
                DLP_LOG_ERROR(LABEL, "systemAbilityManager is null.");
                return nullptr;
            }
            auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleMgrSa == nullptr) {
                DLP_LOG_ERROR(LABEL, "bundleMgrSa is null.");
                return nullptr;
            }
            bundleMgr_ = OHOS::iface_cast<AppExecFwk::IBundleMgr>(bundleMgrSa);
            if (bundleMgr_ == nullptr) {
                DLP_LOG_ERROR(LABEL, "iface_cast failed.");
                return nullptr;
            }
        }
    }
    return bundleMgr_;
}

bool SandboxJsonManager::InsertSandboxInfo(std::set<std::string> docUriSet, uint32_t tokenId, std::string bundleName,
    int32_t appIndex, int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        if (iter->tokenId == tokenId) {
            DLP_LOG_ERROR(LABEL, "docUri exist tokenId:%{public}d,bundleName:%{public}s,int32_t:%{public}d", tokenId,
                bundleName.c_str(), appIndex);
            return false;
        }
    }
    RetentionInfo info;
    info.tokenId = tokenId;
    info.bundleName = bundleName;
    info.appIndex = appIndex;
    info.userId = userId;
    info.docUriSet = docUriSet;
    infoVec_.push_back(info);
    return true;
}

void SandboxJsonManager::RetentionInfoToJson(Json& json, const RetentionInfo& info) const
{
    json = Json { { APPINDEX, info.appIndex },
        { TOKENID, info.tokenId },
        { BUNDLENAME, info.bundleName },
        { USERID, info.userId },
        { DOCURISET, info.docUriSet } };
}

Json SandboxJsonManager::ToJson() const
{
    Json jsonObject;
    for (auto iter = infoVec_.begin(); iter != infoVec_.end(); ++iter) {
        Json infoJson;
        RetentionInfoToJson(infoJson, *iter);
        jsonObject["retention"].push_back(infoJson);
    }
    return jsonObject;
}

void SandboxJsonManager::FromJson(const Json& jsonObject)
{
    if (jsonObject.is_null() || jsonObject.is_discarded()) {
        DLP_LOG_ERROR(LABEL, "json error");
        return;
    }
    for (auto& retentionJson : jsonObject["retention"]) {
        std::string bundleName;
        uint32_t tokenId;
        std::set<std::string> docUriSet;
        int32_t appIndex;
        int32_t userId;
        if (!retentionJson.contains(APPINDEX) || !retentionJson.at(APPINDEX).is_number() ||
            !retentionJson.contains(BUNDLENAME) || !retentionJson.at(BUNDLENAME).is_string() ||
            !retentionJson.contains(DOCURISET) || !retentionJson.at(DOCURISET).is_array() ||
            !retentionJson.contains(TOKENID) || !retentionJson.at(TOKENID).is_number() ||
            !retentionJson.contains(USERID) || !retentionJson.at(USERID).is_number()) {
            DLP_LOG_ERROR(LABEL, "json contains error");
        }
        retentionJson.at(APPINDEX).get_to(appIndex);
        retentionJson.at(BUNDLENAME).get_to(bundleName);
        retentionJson.at(DOCURISET).get_to(docUriSet);
        retentionJson.at(TOKENID).get_to(tokenId);
        retentionJson.at(USERID).get_to(userId);
        if (bundleName.empty() || appIndex < 0 || userId < 0 || tokenId == 0) {
            DLP_LOG_ERROR(LABEL, "param is invalid");
            return;
        }
        InsertSandboxInfo(docUriSet, tokenId, bundleName, appIndex, userId);
    }
}

std::string SandboxJsonManager::ToString() const
{
    if (infoVec_.empty()) {
        return "";
    }
    auto jsonObject = ToJson();
    return jsonObject.dump();
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS