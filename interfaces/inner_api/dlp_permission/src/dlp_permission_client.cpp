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

#include "dlp_permission_client.h"
#include <unistd.h>
#include "accesstoken_kit.h"
#include "dlp_policy.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_load_callback.h"
#include "dlp_permission_log.h"
#include "dlp_permission_proxy.h"
#include "iservice_registry.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionClient"};
static const int32_t DLP_PERMISSION_LOAD_SA_TIMEOUT_MS = 1000;
static const std::string ALLOW_ABILITY[] = {"com.ohos.permissionmanager"};
}  // namespace

DlpPermissionClient& DlpPermissionClient::GetInstance()
{
    static DlpPermissionClient instance;
    return instance;
}

DlpPermissionClient::DlpPermissionClient()
{}

DlpPermissionClient::~DlpPermissionClient()
{
    if (proxy_ == nullptr) {
        return;
    }
    auto remoteObj = proxy_->AsObject();
    if (remoteObj == nullptr) {
        return;
    }
    if (serviceDeathObserver_ != nullptr) {
        remoteObj->RemoveDeathRecipient(serviceDeathObserver_);
    }
}

static int32_t CheckSandboxFlag(AccessToken::AccessTokenID tokenId, bool& sandboxFlag)
{
    int32_t res = AccessToken::AccessTokenKit::GetHapDlpFlag(tokenId);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Invalid tokenId");
        return res;
    }
    sandboxFlag = (res == 1);
    return DLP_OK;
}

int32_t DlpPermissionClient::GenerateDlpCertificate(
    const PermissionPolicy& policy, std::shared_ptr<GenerateDlpCertificateCallback> callback)
{
    if (!policy.IsValid() || callback == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    policyParcel->policyParams_.CopyPermissionPolicy(policy);

    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (asyncStub == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }

    return proxy->GenerateDlpCertificate(policyParcel, asyncStub);
}

int32_t DlpPermissionClient::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, uint32_t flag, std::shared_ptr<ParseDlpCertificateCallback> callback)
{
    if (callback == nullptr || cert.size() == 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (asyncStub == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }

    return proxy->ParseDlpCertificate(cert, flag, asyncStub);
}

int32_t DlpPermissionClient::InstallDlpSandbox(const std::string& bundleName, AuthPermType permType, int32_t userId,
    int32_t& appIndex, const std::string& uri)
{
    if (bundleName.empty() || permType >= DEFAULT_PERM || permType < READ_ONLY || uri.empty()) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    return proxy->InstallDlpSandbox(bundleName, permType, userId, appIndex, uri);
}

int32_t DlpPermissionClient::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    if (bundleName.empty() || appIndex < 0 || userId < 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    return proxy->UninstallDlpSandbox(bundleName, appIndex, userId);
}

static bool CheckAllowAbilityList(const std::string& bundleName)
{
    return std::any_of(std::begin(ALLOW_ABILITY), std::end(ALLOW_ABILITY),
        [bundleName](const std::string& bundle) { return bundle == bundleName; });
}

int32_t DlpPermissionClient::GetSandboxExternalAuthorization(
    int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& auth)
{
    if (CheckAllowAbilityList(want.GetBundle())) {
        auth = ALLOW_START_ABILITY;
        return DLP_OK;
    }
    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null, dlpmanager service no start.");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    if (sandboxUid < 0) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    return proxy->GetSandboxExternalAuthorization(sandboxUid, want, auth);
}

int32_t DlpPermissionClient::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    bool sandboxFlag;
    if ((tokenId == 0) || (CheckSandboxFlag(tokenId, sandboxFlag) != DLP_OK)) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!sandboxFlag) {
        DLP_LOG_INFO(LABEL, "it is not a sandbox app");
        copyable = true;
        return DLP_OK;
    }

    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        copyable = false;
        return DLP_OK;
    }

    return proxy->QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

int32_t DlpPermissionClient::QueryDlpFileAccess(DLPPermissionInfo& permInfo)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetSelfTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!sandboxFlag) {
        DLP_LOG_INFO(LABEL, "it is not a sandbox app");
        return DLP_OK;
    }

    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_OK;
    }
    sptr<DLPPermissionInfoParcel> permInfoyParcel = new (std::nothrow) DLPPermissionInfoParcel();
    if (permInfoyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t result = proxy->QueryDlpFileAccess(*permInfoyParcel);
    if (result != DLP_OK) {
        return result;
    }
    permInfo = permInfoyParcel->permInfo_;
    return result;
}

int32_t DlpPermissionClient::IsInDlpSandbox(bool& inSandbox)
{
    bool sandboxFlag;
    if (CheckSandboxFlag(GetSelfTokenID(), sandboxFlag) != DLP_OK) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    if (!sandboxFlag) {
        DLP_LOG_INFO(LABEL, "it is not a sandbox app");
        inSandbox = false;
        return DLP_OK;
    }

    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        inSandbox = true;
        return DLP_OK;
    }

    return proxy->IsInDlpSandbox(inSandbox);
}

int32_t DlpPermissionClient::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_OK;
    }

    return proxy->GetDlpSupportFileType(supportFileType);
}

int32_t DlpPermissionClient::CreateDlpSandboxChangeCallback(
    const std::shared_ptr<DlpSandboxChangeCallbackCustomize> &customizedCb, sptr<DlpSandboxChangeCallback> &callback)
{
    callback = new (std::nothrow) DlpSandboxChangeCallback(customizedCb);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "memory allocation for callback failed!");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }
    return DLP_OK;
}

int32_t DlpPermissionClient::RegisterDlpSandboxChangeCallback(
    const std::shared_ptr<DlpSandboxChangeCallbackCustomize> &customizedCb)
{
    if (customizedCb == nullptr) {
        DLP_LOG_ERROR(LABEL, "customizedCb is nullptr");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    sptr<DlpSandboxChangeCallback> callback = nullptr;
    int32_t result = CreateDlpSandboxChangeCallback(customizedCb, callback);
    if (result != DLP_OK) {
        return result;
    }
    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }
    return proxy->RegisterDlpSandboxChangeCallback(callback->AsObject());
}

int32_t DlpPermissionClient::UnregisterDlpSandboxChangeCallback(bool &result)
{
    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->UnRegisterDlpSandboxChangeCallback(result);
}

int32_t DlpPermissionClient::GetDlpGatheringPolicy(bool& isGathering)
{
    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_OK;
    }

    return proxy->GetDlpGatheringPolicy(isGathering);
}

int32_t DlpPermissionClient::SetRetentionState(const std::vector<std::string>& docUriVec)
{
    auto proxy = GetProxy(false);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->SetRetentionState(docUriVec);
}

int32_t DlpPermissionClient::SetNonRetentionState(const std::vector<std::string>& docUriVec)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->SetNonRetentionState(docUriVec);
}

int32_t DlpPermissionClient::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
}

int32_t DlpPermissionClient::ClearUnreservedSandbox()
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->ClearUnreservedSandbox();
}

int32_t DlpPermissionClient::GetDLPFileVisitRecord(std::vector<VisitedDLPFileInfo>& infoVec)
{
    auto proxy = GetProxy(true);
    if (proxy == nullptr) {
        DLP_LOG_INFO(LABEL, "Proxy is null");
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    return proxy->GetDLPFileVisitRecord(infoVec);
}

bool DlpPermissionClient::StartLoadDlpPermissionSa()
{
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        readyFlag_ = false;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return false;
    }

    sptr<DlpPermissionLoadCallback> ptrDlpPermissionLoadCallback = new (std::nothrow) DlpPermissionLoadCallback();
    if (ptrDlpPermissionLoadCallback == nullptr) {
        DLP_LOG_ERROR(LABEL, "New ptrDlpPermissionLoadCallback fail.");
        return false;
    }

    int32_t result = sam->LoadSystemAbility(SA_ID_DLP_PERMISSION_SERVICE, ptrDlpPermissionLoadCallback);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "LoadSystemAbility %{public}d failed", SA_ID_DLP_PERMISSION_SERVICE);
        return false;
    }
    DLP_LOG_INFO(LABEL, "Notify samgr load sa %{public}d success", SA_ID_DLP_PERMISSION_SERVICE);
    return true;
}

void DlpPermissionClient::WaitForDlpPermissionSa()
{
    // wait_for release lock and block until time out(1s) or match the condition with notice
    std::unique_lock<std::mutex> lock(cvLock_);
    auto waitStatus = dlpPermissionCon_.wait_for(
        lock, std::chrono::milliseconds(DLP_PERMISSION_LOAD_SA_TIMEOUT_MS), [this]() { return readyFlag_; });
    if (!waitStatus) {
        // time out or loadcallback fail
        DLP_LOG_ERROR(LABEL, "Dlp Permission load sa timeout");
        return;
    }
}

void DlpPermissionClient::GetDlpPermissionSa()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return;
    }

    auto dlpPermissionSa = sam->GetSystemAbility(SA_ID_DLP_PERMISSION_SERVICE);
    if (dlpPermissionSa == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null", SA_ID_DLP_PERMISSION_SERVICE);
        return;
    }

    GetProxyFromRemoteObject(dlpPermissionSa);
}

void DlpPermissionClient::FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject)
{
    DLP_LOG_INFO(LABEL, "Get dlp_permission sa success.");

    GetProxyFromRemoteObject(remoteObject);

    // get lock which wait_for release and send a notice so that wait_for can out of block
    std::unique_lock<std::mutex> lock(cvLock_);
    readyFlag_ = true;
    dlpPermissionCon_.notify_one();
}

void DlpPermissionClient::FinishStartSAFail()
{
    DLP_LOG_ERROR(LABEL, "get dlp_permission sa failed.");

    // get lock which wait_for release and send a notice
    std::unique_lock<std::mutex> lock(cvLock_);
    readyFlag_ = true;
    dlpPermissionCon_.notify_one();
}

void DlpPermissionClient::LoadDlpPermissionSa()
{
    if (!StartLoadDlpPermissionSa()) {
        return;
    }
    WaitForDlpPermissionSa();
}

void DlpPermissionClient::OnRemoteDiedHandle()
{
    DLP_LOG_ERROR(LABEL, "Remote service died");
    std::unique_lock<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
    {
        std::unique_lock<std::mutex> lock1(cvLock_);
        readyFlag_ = false;
    }
}

void DlpPermissionClient::GetProxyFromRemoteObject(const sptr<IRemoteObject>& remoteObject)
{
    if (remoteObject == nullptr) {
        return;
    }

    sptr<DlpPermissionDeathRecipient> serviceDeathObserver = new (std::nothrow) DlpPermissionDeathRecipient();
    if (serviceDeathObserver == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc service death observer fail");
        return;
    }

    if (!remoteObject->AddDeathRecipient(serviceDeathObserver)) {
        DLP_LOG_ERROR(LABEL, "Add service death observer fail");
        return;
    }

    auto proxy = iface_cast<IDlpPermissionService>(remoteObject);
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "iface_cast get null");
        return;
    }
    proxy_ = proxy;
    serviceDeathObserver_ = serviceDeathObserver;
    DLP_LOG_INFO(LABEL, "GetSystemAbility %{public}d success", SA_ID_DLP_PERMISSION_SERVICE);
    return;
}

sptr<IDlpPermissionService> DlpPermissionClient::GetProxy(bool doLoadSa)
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    if (doLoadSa) {
        LoadDlpPermissionSa();
    } else {
        GetDlpPermissionSa();
    }
    return proxy_;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
