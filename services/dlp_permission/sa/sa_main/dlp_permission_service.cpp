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

#include "dlp_permission_service.h"
#include "accesstoken_kit.h"
#include "bundle_mgr_client.h"
#include "dlp_credential_service.h"
#include "dlp_credential_adapt.h"
#include "dlp_permission.h"
#include "dlp_policy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_sandbox_info.h"
#include "dlp_permission_serializer.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionService"};
}
REGISTER_SYSTEM_ABILITY_BY_ID(DlpPermissionService, SA_ID_DLP_PERMISSION_SERVICE, true);

DlpPermissionService::DlpPermissionService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
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
    state_ = ServiceRunningState::STATE_NOT_START;
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

    DlpCredential::GetInstance().GenerateDlpCertificate(
        jsonObj.dump(), policyParcel->policyParams_.ownerAccountType_, callback);

    return DLP_OK;
}

int32_t DlpPermissionService::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, sptr<IDlpPermissionCallback>& callback)
{
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    DlpCredential::GetInstance().ParseDlpCertificate(cert, callback);

    return DLP_OK;
}

void DlpPermissionService::InsertDlpSandboxInfo(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t appIndex)
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

int32_t DlpPermissionService::InstallDlpSandbox(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex)
{
    if (bundleName.empty() || permType >= DEFAULT_PERM || permType < READ_ONLY) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    AppExecFwk::BundleMgrClient bundleMgrClient;
    int32_t res = bundleMgrClient.InstallSandboxApp(bundleName, permType, userId, appIndex);
    if (res != DLP_OK) {
        return res;
    }
    InsertDlpSandboxInfo(bundleName, permType, userId, appIndex);
    return DLP_OK;
}

void DlpPermissionService::DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (appStateObserver_ == nullptr) {
        DLP_LOG_WARN(LABEL, "Failed to get app state observer instance");
        return;
    }

    AppExecFwk::BundleMgrClient bundleMgrClient;
    AppExecFwk::BundleInfo info;
    int32_t result = bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get sandbox bundle info fail");
        return;
    }

    appStateObserver_->EraseDlpSandboxInfo(info.uid);
    return;
}

int32_t DlpPermissionService::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (bundleName.empty() || appIndex < 0 || userId < 0) {
        DLP_LOG_ERROR(LABEL, "param is invalid");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    DeleteDlpSandboxInfo(bundleName, appIndex, userId);
    AppExecFwk::BundleMgrClient bundleMgrClient;
    return bundleMgrClient.UninstallSandboxApp(bundleName, appIndex, userId);
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
    if (isSandbox) {
        authType = DENY_START_ABILITY;
    } else {
        authType = ALLOW_START_ABILITY;
    }
    return DLP_OK;
}

int32_t DlpPermissionService::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    if (tokenId <= 0) {
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
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
