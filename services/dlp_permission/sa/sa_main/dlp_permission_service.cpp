/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dlp_permission_service.h"
#include <chrono>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "app_mgr_client.h"
#include "bundle_mgr_client.h"
#include "callback_manager.h"
#include "dlp_credential_client.h"
#include "dlp_credential_adapt.h"
#include "dlp_permission.h"
#include "dlp_policy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_sandbox_info.h"
#include "dlp_permission_serializer.h"
#include "hap_token_info.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#if defined(DLP_DEBUG_ENABLE) && DLP_DEBUG_ENABLE == 1
#include "parameter.h"
#endif
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace Security::AccessToken;
using namespace OHOS::AppExecFwk;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionService" };
static const std::string ALLOW_ABILITY[] = {"com.ohos.dlpmanager"};
static const std::string DLP_MANAGER = "com.ohos.dlpmanager";
static const std::chrono::seconds SLEEP_TIME(120);
static const int REPEAT_TIME = 5;
}
REGISTER_SYSTEM_ABILITY_BY_ID(DlpPermissionService, SA_ID_DLP_PERMISSION_SERVICE, true);

DlpPermissionService::DlpPermissionService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    thread_ = nullptr;
    DLP_LOG_INFO(LABEL, "DlpPermissionService()");
}

DlpPermissionService::~DlpPermissionService()
{
    DLP_LOG_INFO(LABEL, "~DlpPermissionService()");
    UnregisterAppStateObserver();
    iAppMgr_ = nullptr;
    appStateObserver_ = nullptr;
}

void DlpPermissionService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        DLP_LOG_INFO(LABEL, "DlpPermissionService has already started!");
        return;
    }
    DLP_LOG_INFO(LABEL, "DlpPermissionService is starting");
    if (!RegisterAppStateObserver()) {
        DLP_LOG_ERROR(LABEL, "Failed to register app state observer!");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(this);
    if (!ret) {
        DLP_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    DLP_LOG_INFO(LABEL, "Congratulations, DlpPermissionService start successfully!");
}

void DlpPermissionService::OnStop()
{
    DLP_LOG_INFO(LABEL, "Stop service");
}

bool DlpPermissionService::RegisterAppStateObserver()
{
    if (appStateObserver_ != nullptr) {
        DLP_LOG_INFO(LABEL, "AppStateObserver instance already create");
        return true;
    }
    appStateObserver_ = new (std::nothrow) AppStateObserver();
    if (appStateObserver_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to create AppStateObserver instance");
        return false;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get system ability manager");
        appStateObserver_ = nullptr;
        return false;
    }
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppMgr_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get ability manager service");
        appStateObserver_ = nullptr;
        return false;
    }
    int32_t result = iAppMgr_->RegisterApplicationStateObserver(appStateObserver_);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Failed to Register app state observer");
        iAppMgr_ = nullptr;
        appStateObserver_ = nullptr;
        return false;
    }
    return true;
}

void DlpPermissionService::UnregisterAppStateObserver()
{
    if (iAppMgr_ != nullptr && appStateObserver_ != nullptr) {
        iAppMgr_->UnregisterApplicationStateObserver(appStateObserver_);
    }
}

int32_t DlpPermissionService::GenerateDlpCertificate(
    const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!policyParcel->policyParams_.IsValid()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    nlohmann::json jsonObj;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeDlpPermission(policyParcel->policyParams_, jsonObj);
    if (res != DLP_OK) {
        return res;
    }

    return DlpCredential::GetInstance().GenerateDlpCertificate(
        jsonObj.dump(), policyParcel->policyParams_.ownerAccountType_, callback);
}

int32_t DlpPermissionService::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, uint32_t flag, sptr<IDlpPermissionCallback>& callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    return DlpCredential::GetInstance().ParseDlpCertificate(cert, flag, callback);
}

void DlpPermissionService::InsertDlpSandboxInfo(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t appIndex, int32_t pid)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return;
    }

    DlpSandboxInfo sandboxInfo;
    sandboxInfo.permType = permType;
    sandboxInfo.bundleName = bundleName;
    sandboxInfo.userId = userId;
    sandboxInfo.appIndex = appIndex;
    sandboxInfo.pid = pid;
    AppExecFwk::BundleInfo info;
    AppExecFwk::BundleMgrClient bundleMgrClient;
    if (bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        return;
    } else {
        sandboxInfo.uid = info.uid;
    }
    sandboxInfo.tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    appStateObserver_->AddDlpSandboxInfo(sandboxInfo);
    return;
}

int32_t DlpPermissionService::InstallDlpSandbox(const std::string& bundleName, AuthPermType permType, int32_t userId,
    int32_t& appIndex, const std::string& uri)
{
    if (bundleName.empty() || permType >= DEFAULT_PERM || permType < READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    std::vector<RetentionSandBoxInfo> infoVec;
    auto res = RetentionFileManager::GetInstance().GetRetentionSandboxList(bundleName, infoVec, true);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetRetentionSandboxList fail bundleName:%{public}s,uri:%{public}s, error=%{public}d",
            bundleName.c_str(), uri.c_str(), res);
        return res;
    }
    bool isNeedInstall = true;
    for (auto iter = infoVec.begin(); iter != infoVec.end(); ++iter) {
        auto setIter = iter->docUriSet_.find(uri);
        if (setIter != iter->docUriSet_.end()) {
            appIndex = iter->appIndex_;
            isNeedInstall = false;
            break;
        }
    }
    if (isNeedInstall) {
        AppExecFwk::BundleMgrClient bundleMgrClient;
        int32_t bundleClientRes = bundleMgrClient.InstallSandboxApp(bundleName, permType, userId, appIndex);
        if (bundleClientRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "install sandbox %{public}s fail, error=%{public}d", bundleName.c_str(),
                bundleClientRes);
            return DLP_SERVICE_ERROR_INSTALL_SANDBOX_FAIL;
        }
    }
    int32_t pid = IPCSkeleton::GetCallingPid();
    InsertDlpSandboxInfo(bundleName, permType, userId, appIndex, pid);
    return DLP_OK;
}

uint32_t DlpPermissionService::DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return 0;
    }

    AppExecFwk::BundleMgrClient bundleMgrClient;
    AppExecFwk::BundleInfo info;
    int32_t result = bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        return 0;
    }

    return appStateObserver_->EraseDlpSandboxInfo(info.uid);
}

int32_t DlpPermissionService::UninstallDlpSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    AppExecFwk::BundleMgrClient bundleMgrClient;
    int32_t res = bundleMgrClient.UninstallSandboxApp(bundleName, appIndex, userId);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "uninstall sandbox %{public}s fail, index=%{public}d, error=%{public}d",
            bundleName.c_str(), appIndex, res);
        return DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (bundleName.empty() || appIndex < 0 || userId < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    uint32_t tokenId = DeleteDlpSandboxInfo(bundleName, appIndex, userId);
    if (tokenId == 0) {
        DLP_LOG_ERROR(LABEL, "DeleteDlpSandboxInfo sandbox %{public}s fail, index=%{public}d", bundleName.c_str(),
            appIndex);
        return DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL;
    }
    if (RetentionFileManager::GetInstance().CanUninstall(tokenId)) {
        return UninstallDlpSandboxApp(bundleName, appIndex, userId);
    }
    return DLP_OK;
}

static bool CheckAllowAbilityList(const std::string& bundleName)
{
    return std::any_of(std::begin(ALLOW_ABILITY), std::end(ALLOW_ABILITY),
        [bundleName](const std::string& bundle) { return bundle == bundleName; });
}

int32_t DlpPermissionService::GetSandboxExternalAuthorization(
    int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& authType)
{
    if (sandboxUid < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (appStateObserver_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    bool isSandbox = false;
    appStateObserver_->IsInDlpSandbox(isSandbox, sandboxUid);
    if (isSandbox && !CheckAllowAbilityList(want.GetBundle())) {
        authType = DENY_START_ABILITY;
    } else {
        authType = ALLOW_START_ABILITY;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    if (tokenId == 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    return appStateObserver_->QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

int32_t DlpPermissionService::QueryDlpFileAccess(AuthPermType& permType)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    return appStateObserver_->QueryDlpFileAccessByUid(permType, uid);
}

int32_t DlpPermissionService::IsInDlpSandbox(bool& inSandbox)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return DLP_SERVICE_ERROR_APPOBSERVER_NULL;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    return appStateObserver_->IsInDlpSandbox(inSandbox, uid);
}

int32_t DlpPermissionService::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    supportFileType = {
        ".doc", ".docm", ".docx", ".dot", ".dotm", ".dotx", ".odp", ".odt", ".pdf", ".pot", ".potm", ".potx", ".ppa",
        ".ppam", ".pps", ".ppsm", ".ppsx", ".ppt", ".pptm", ".pptx", ".rtf", ".txt", ".wps", ".xla", ".xlam", ".xls",
        ".xlsb", ".xlsm", ".xlsx", ".xlt", ".xltm", ".xltx", ".xlw", ".xml", ".xps"
    };
    return DLP_OK;
}

int32_t DlpPermissionService::RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject> &callback)
{
    int32_t pid = IPCSkeleton::GetCallingPid();
    DLP_LOG_INFO(LABEL, "GetCallingPid,%{public}d", pid);
    return CallbackManager::GetInstance().AddCallback(pid, callback);
}

int32_t DlpPermissionService::UnRegisterDlpSandboxChangeCallback(bool &result)
{
    int32_t pid = IPCSkeleton::GetCallingPid();
    DLP_LOG_INFO(LABEL, "GetCallingPid,%{public}d", pid);
    return CallbackManager::GetInstance().RemoveCallback(pid, result);
}

int32_t DlpPermissionService::GetDlpGatheringPolicy(bool& isGathering)
{
    isGathering = isGathering_;
#if defined(DLP_DEBUG_ENABLE) && DLP_DEBUG_ENABLE == 1
    const char* PARAM_KEY = "dlp.permission.gathering.policy";
    const int32_t VALUE_MAX_LEN = 32;
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(PARAM_KEY, "false", value, VALUE_MAX_LEN - 1);
    if (ret <= 0) {
        DLP_LOG_WARN(LABEL, "Failed to get parameter, %{public}s", PARAM_KEY);
        return DLP_OK;
    }

    std::string tmp(value);
    if (tmp == "true") {
        isGathering = true;
    }

    if (tmp == "false") {
        isGathering = false;
    }
#endif
    return DLP_OK;
}

int32_t DlpPermissionService::SetRetentionState(const std::vector<std::string>& docUriVec)
{
    if (docUriVec.empty()) {
        DLP_LOG_ERROR(LABEL, "get docUriVec empty");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    RetentionInfo info;
    info.tokenId = IPCSkeleton::GetCallingTokenID();
    std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
    return RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
}

int32_t DlpPermissionService::SetNonRetentionState(const std::vector<std::string>& docUriVec)
{
    if (docUriVec.empty()) {
        DLP_LOG_ERROR(LABEL, "get docUriVec empty");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    RetentionInfo info;
    info.tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetCallerBundleName(info.tokenId, info.bundleName)) {
        DLP_LOG_ERROR(LABEL, "get callerBundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    bool isInSandbox = false;
    IsInDlpSandbox(isInSandbox);
    if (!isInSandbox) {
        info.tokenId = 0;
    }
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(terminalMutex_);
        std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
        res = RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, false);
        if (isInSandbox) {
            return res;
        }
        std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
        int32_t getRes = RetentionFileManager::GetInstance().GetRetentionSandboxList(info.bundleName,
            retentionSandBoxInfoVec, false);
        if (getRes != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "getRes != DLP_OK");
            return getRes;
        }
        if (!retentionSandBoxInfoVec.empty()) {
            if (!RemoveRetentionInfo(retentionSandBoxInfoVec, info)) {
                return DLP_SERVICE_ERROR_VALUE_INVALID;
            }
        }
    }
    StartTimer();
    return res;
}

bool DlpPermissionService::RemoveRetentionInfo(std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec,
    RetentionInfo& info)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    if (GetUserIdFromUid(uid, &userId) != 0) {
        DLP_LOG_ERROR(LABEL, "get GetUserIdFromUid error");
        return false;
    }
    for (auto iter = retentionSandBoxInfoVec.begin(); iter != retentionSandBoxInfoVec.end(); ++iter) {
        if (appStateObserver_->CheckSandboxInfo(info.bundleName, iter->appIndex_, userId)) {
            continue;
        }
        DeleteDlpSandboxInfo(info.bundleName, iter->appIndex_, userId);
        UninstallDlpSandboxApp(info.bundleName, iter->appIndex_, userId);
        RetentionFileManager::GetInstance().RemoveRetentionState(info.bundleName, iter->appIndex_);
    }
    return true;
}

void DlpPermissionService::StartTimer()
{
    repeatTime_ = REPEAT_TIME;
    std::lock_guard<std::mutex> lock(mutex_);
    if (thread_ != nullptr && !thread_->joinable()) { // avoid double assign to an active thread
        DLP_LOG_ERROR(LABEL, "thread is active");
        return;
    }
    thread_ = std::make_shared<std::thread>(&DlpPermissionService::TerminalService, this);
    thread_->detach();
    return;
}

void DlpPermissionService::TerminalService()
{
    DLP_LOG_DEBUG(LABEL, "enter");
    int32_t remainingTime = repeatTime_.load();
    while (remainingTime > 0) {
        std::this_thread::sleep_for(SLEEP_TIME);
        repeatTime_--;
        remainingTime = repeatTime_.load();
        DLP_LOG_DEBUG(LABEL, "repeatTime_ %{public}d", remainingTime);
    }
    std::lock_guard<std::mutex> lock(terminalMutex_);
    appStateObserver_->ExitSaAfterAllDlpManagerDie();
}

int32_t DlpPermissionService::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    std::string callerBundleName;
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    GetCallerBundleName(tokenId, callerBundleName);
    bool isNeedTimer = true;
    if (callerBundleName == DLP_MANAGER) {
        callerBundleName = bundleName;
        isNeedTimer = false;
    }
    if (bundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "get bundleName error");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto res =
        RetentionFileManager::GetInstance().GetRetentionSandboxList(callerBundleName, retentionSandBoxInfoVec, true);
    if (!isNeedTimer) {
        return res;
    }
    StartTimer();
    return res;
}

int32_t DlpPermissionService::ClearUnreservedSandbox()
{
    RetentionFileManager::GetInstance().ClearUnreservedSandbox();
    StartTimer();
    return DLP_OK;
}

bool DlpPermissionService::GetCallerBundleName(const uint32_t tokenId, std::string& bundleName)
{
    HapTokenInfo tokenInfo;
    auto result = AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo);
    if (result != RET_SUCCESS) {
        DLP_LOG_ERROR(LABEL, "token:0x%{public}x, result:%{public}d", tokenId, result);
        return false;
    }
    if (tokenInfo.bundleName.empty()) {
        DLP_LOG_ERROR(LABEL, "bundlename is empty");
        return false;
    }
    bundleName = tokenInfo.bundleName;
    return true;
}

int DlpPermissionService::Dump(int fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        return ERR_INVALID_VALUE;
    }

    dprintf(fd, "DlpPermission Dump:\n");
    std::string arg0 = (args.size() == 0) ? "" : Str16ToStr8(args.at(0));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help\n");
        dprintf(fd, "      -d: default dump\n");
    } else if (arg0.compare("-d") == 0 || arg0.compare("") == 0) {
        if (appStateObserver_ != nullptr) {
            appStateObserver_->DumpSandbox(fd);
        } else {
            return ERR_INVALID_VALUE;
        }
    }

    return ERR_OK;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
