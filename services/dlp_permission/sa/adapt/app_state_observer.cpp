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

#include "app_state_observer.h"
#include <unistd.h>
#include "account_adapt.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "bundle_mgr_client.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppStateObserver"};
}
AppStateObserver::AppStateObserver()
{}

AppStateObserver::~AppStateObserver()
{
    UninstallAllDlpSandbox();
}

void AppStateObserver::UninstallDlpSandbox(DlpSandboxInfo& appInfo)
{
    if (appInfo.appIndex <= 0) {  // never uninstall original hap
        return;
    }
    auto sandboxBundleName = appInfo.bundleName + std::to_string(appInfo.appIndex);
    DLP_LOG_INFO(LABEL, "uninstall dlp sandbox %{public}s, uid: %{public}d", sandboxBundleName.c_str(), appInfo.uid);
    AppExecFwk::BundleMgrClient bundleMgrClient;
    bundleMgrClient.UninstallSandboxApp(appInfo.bundleName, appInfo.appIndex, appInfo.userId);
}

void AppStateObserver::UninstallAllDlpSandboxForUser(int32_t userId)
{
    AppExecFwk::BundleMgrClient bundleMgrClient;
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    for (auto iter = sandboxInfo_.begin(); iter != sandboxInfo_.end();) {
        auto& appInfo = iter->second;
        if (appInfo.userId != userId) {
            ++iter;
            continue;
        }
        UninstallDlpSandbox(appInfo);
        EraseUidTokenIdMap(appInfo.tokenId);
        sandboxInfo_.erase(iter++);
    }
}

void AppStateObserver::UninstallAllDlpSandbox()
{
    DLP_LOG_INFO(LABEL, "service exit, uninstall all dlp sandbox");
    std::lock_guard<std::mutex> lock(userIdListLock_);
    for (const auto& iter : userIdList_) {
        UninstallAllDlpSandboxForUser(iter);
    }
    userIdList_.clear();
}

void AppStateObserver::ExitSaAfterAllDlpManagerDie()
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    if (userIdList_.empty()) {
        DLP_LOG_INFO(LABEL, "all dlp manager app die, service exit");
        exit(0);
    }
}

void AppStateObserver::EraseUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    auto iter = userIdList_.find(userId);
    if (iter != userIdList_.end()) {
        DLP_LOG_INFO(LABEL, "erase userId %{public}d", userId);
        userIdList_.erase(userId);
    }
    if (userIdList_.empty()) {
        exit(0);
    }
}

void AppStateObserver::AddUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(userIdListLock_);
    if (userIdList_.count(userId) <= 0) {
        DLP_LOG_INFO(LABEL, "add userId %{public}d", userId);
        userIdList_.emplace(userId);
    }
    return;
}

bool AppStateObserver::GetSandboxInfo(int32_t uid, DlpSandboxInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    auto iter = sandboxInfo_.find(uid);
    if (iter != sandboxInfo_.end()) {
        appInfo = iter->second;
        return true;
    }
    return false;
}

void AppStateObserver::EraseSandboxInfo(int32_t uid)
{
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    auto iter = sandboxInfo_.find(uid);
    if (iter != sandboxInfo_.end()) {
        auto sandboxBundleName = iter->second.bundleName + std::to_string(iter->second.appIndex);
        DLP_LOG_INFO(LABEL, "sandbox app %{public}s info delete success, uid: %{public}d", sandboxBundleName.c_str(),
            iter->second.uid);
        sandboxInfo_.erase(iter);
    }
}

void AppStateObserver::AddSandboxInfo(const DlpSandboxInfo& appInfo)
{
    auto sandboxBundleName = appInfo.bundleName + std::to_string(appInfo.appIndex);
    std::lock_guard<std::mutex> lock(sandboxInfoLock_);
    if (sandboxInfo_.count(appInfo.uid) > 0) {
        DLP_LOG_WARN(LABEL, "sandbox app %{public}s is already insert, ignore it", sandboxBundleName.c_str());
    } else {
        sandboxInfo_[appInfo.uid] = appInfo;
        DLP_LOG_INFO(LABEL, "sandbox app %{public}s info insert success, uid: %{public}d", sandboxBundleName.c_str(),
            appInfo.uid);
    }
    return;
}

void AppStateObserver::AddDlpSandboxInfo(const DlpSandboxInfo& appInfo)
{
    int32_t userId;
    if (GetUserIdFromUid(appInfo.uid, &userId) != 0) {
        return;
    }
    AddUserId(userId);
    AddSandboxInfo(appInfo);
    AddUidWithTokenId(appInfo.tokenId, appInfo.uid);
    return;
}

void AppStateObserver::EraseDlpSandboxInfo(int uid)
{
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(uid, appInfo)) {
        return;
    }
    auto sandboxBundleName = appInfo.bundleName + std::to_string(appInfo.appIndex);
    EraseSandboxInfo(appInfo.uid);
    EraseUidTokenIdMap(appInfo.tokenId);
}

void AppStateObserver::OnProcessDied(const AppExecFwk::ProcessData& processData)
{
    DLP_LOG_INFO(LABEL, "%{public}s is died, uid: %{public}d", processData.bundleName.c_str(), processData.uid);

    // current died process is dlpmanager
    if (processData.bundleName == "com.ohos.dlpmanager") {
        int32_t userId;
        if (GetUserIdFromUid(processData.uid, &userId) != 0) {
            return;
        }
        DLP_LOG_INFO(LABEL, "%{public}s in userId %{public}d is died", processData.bundleName.c_str(), userId);
        UninstallAllDlpSandboxForUser(userId);
        EraseUserId(userId);
        ExitSaAfterAllDlpManagerDie();
        return;
    }

    // current died process is dlp sandbox app
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(processData.uid, appInfo)) {
        return;
    }
    EraseDlpSandboxInfo(appInfo.uid);
    UninstallDlpSandbox(appInfo);
}

void AppStateObserver::EraseUidTokenIdMap(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    auto iter = tokenIdToUidMap_.find(tokenId);
    if (iter != tokenIdToUidMap_.end()) {
        DLP_LOG_INFO(LABEL, "erase tokenId: %{public}d", tokenId);
        tokenIdToUidMap_.erase(iter);
    }
}

void AppStateObserver::AddUidWithTokenId(uint32_t tokenId, int32_t uid)
{
    if (tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "tokenId is invalid");
        return;
    }
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    if (tokenIdToUidMap_.count(tokenId) > 0) {
        return;
    }
    DLP_LOG_INFO(LABEL, "add tokenId: %{public}d, uid: %{public}d", tokenId, uid);
    tokenIdToUidMap_[tokenId] = uid;
}

bool AppStateObserver::GetUidByTokenId(uint32_t tokenId, int32_t& uid)
{
    std::lock_guard<std::mutex> lock(tokenIdToUidMapLock_);
    auto iter = tokenIdToUidMap_.find(tokenId);
    if (iter != tokenIdToUidMap_.end()) {
        DLP_LOG_INFO(LABEL, "tokenId: %{public}d, uid: %{public}d", tokenId, uid);
        uid = iter->second;
        return true;
    }
    return false;
}

static bool IsCopyable(AuthPermType permType)
{
    switch (permType) {
        case READ_ONLY:
            return false;
        case FULL_CONTROL:
            return true;
        default:
            return false;
    }
}

int32_t AppStateObserver::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    int32_t uid;
    copyable = false;
    if (!GetUidByTokenId(tokenId, uid)) {
        DLP_LOG_WARN(LABEL, "current tokenId %{public}d is not a sandbox app", tokenId);
        copyable = false;
        return DLP_SERVICE_ERROR_APPOBSERVER_ERROR;
    }
    AuthPermType permType = DEFAULT_PERM;
    int32_t res = QueryDlpFileAccessByUid(permType, uid);
    if (res != DLP_OK) {
        copyable = false;
    } else {
        copyable = IsCopyable(permType);
    }
    return res;
}

int32_t AppStateObserver::QueryDlpFileAccessByUid(AuthPermType& permType, int32_t uid)
{
    DlpSandboxInfo appInfo;
    if (!GetSandboxInfo(uid, appInfo) || appInfo.permType == DEFAULT_PERM) {
        DLP_LOG_ERROR(LABEL, "current uid %{public}d is not a sandbox app", uid);
        permType = DEFAULT_PERM;
        return DLP_SERVICE_ERROR_APPOBSERVER_ERROR;
    }
    permType = appInfo.permType;
    auto sandboxBundleName = appInfo.bundleName + std::to_string(appInfo.appIndex);
    DLP_LOG_INFO(
        LABEL, "current dlp sandbox %{public}s's perm type is %{public}d", sandboxBundleName.c_str(), permType);
    return DLP_OK;
}

int32_t AppStateObserver::IsInDlpSandbox(bool& inSandbox, int32_t uid)
{
    inSandbox = false;
    DlpSandboxInfo appInfo;
    if (GetSandboxInfo(uid, appInfo)) {
        inSandbox = appInfo.appIndex > 0 ? true : false;
    }
    DLP_LOG_INFO(LABEL, "uid: %{public}d, inSandbox: %{public}d", uid, inSandbox);
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
