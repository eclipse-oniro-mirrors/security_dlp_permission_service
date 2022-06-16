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

#include "dlp_permission_client.h"
#include "dlp_policy_helper.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_load_callback.h"
#include "dlp_permission_log.h"
#include "dlp_permission_policy_def.h"
#include "dlp_permission_proxy.h"
#include "iservice_registry.h"
#include <unistd.h>

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionClient"};
static const int DLP_PERMISSION_LOAD_SA_TIMEOUT_MS = 60000;
}  // namespace

DlpPermissionClient& DlpPermissionClient::GetInstance()
{
    static DlpPermissionClient instance;
    return instance;
}

DlpPermissionClient::DlpPermissionClient()
{}

DlpPermissionClient::~DlpPermissionClient()
{}

int32_t DlpPermissionClient::GenerateDlpCertificate(
    const PermissionPolicy& policy, AccountType accountType, std::shared_ptr<GenerateDlpCertificateCallback> callback)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (!CheckPermissionPolicy(policy) || !CheckAccountType(accountType) || callback == nullptr) {
        return DLP_VALUE_INVALID;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_VALUE_INVALID;
    }

    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_VALUE_INVALID;
    }
    policyParcel->policyParams_ = policy;

    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (asyncStub == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_VALUE_INVALID;
    }

    return proxy->GenerateDlpCertificate(policyParcel, accountType, asyncStub);
}

int32_t DlpPermissionClient::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, std::shared_ptr<ParseDlpCertificateCallback> callback)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (callback == nullptr || cert.size() == 0) {
        return DLP_VALUE_INVALID;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_VALUE_INVALID;
    }

    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (asyncStub == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_VALUE_INVALID;
    }

    return proxy->ParseDlpCertificate(cert, asyncStub);
}

int32_t DlpPermissionClient::InstallDlpSandbox(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (bundleName.empty() || permType >= PERM_MAX || permType < READ_ONLY) {
        return DLP_VALUE_INVALID;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "Proxy is null");
        return DLP_VALUE_INVALID;
    }

    return proxy->InstallDlpSandbox(bundleName, permType, userId, appIndex);
}

void DlpPermissionClient::LoadDlpPermission()
{
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        readyFlag_ = false;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return;
    }

    sptr<DlpPermissionLoadCallback> ptrDlpPermissionLoadCallback = new (std::nothrow) DlpPermissionLoadCallback();
    if (ptrDlpPermissionLoadCallback == nullptr) {
        DLP_LOG_ERROR(LABEL, "New ptrDlpPermissionLoadCallback fail.");
        return;
    }

    int32_t result = sam->LoadSystemAbility(SA_ID_DLP_PERMISSION_SERVICE, ptrDlpPermissionLoadCallback);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "LoadSystemAbility %{public}d failed", SA_ID_DLP_PERMISSION_SERVICE);
        return;
    }
    DLP_LOG_ERROR(LABEL, "LoadSystemAbility!");
}

void DlpPermissionClient::FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject)
{
    DLP_LOG_INFO(LABEL, "Get dlp_permission sa success.");

    SetRemoteObject(remoteObject);

    // get lock which wait_for release and send a notice so that wait_for can out of block
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        readyFlag_ = true;
    }
    dlpPermissionCon_.notify_one();
}

void DlpPermissionClient::FinishStartSAFail()
{
    DLP_LOG_ERROR(LABEL, "get dlp_permission sa failed.");

    SetRemoteObject(nullptr);

    // get lock which wait_for release and send a notice
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        readyFlag_ = true;
    }
    dlpPermissionCon_.notify_one();
}

void DlpPermissionClient::InitProxy()
{
    LoadDlpPermission();
    // wait_for release lock and block until time out(60s) or match the condition with notice
    {
        std::unique_lock<std::mutex> lock(cvLock_);
        auto waitStatus = dlpPermissionCon_.wait_for(
            lock, std::chrono::milliseconds(DLP_PERMISSION_LOAD_SA_TIMEOUT_MS), [this]() { return readyFlag_; });
        if (!waitStatus) {
            // time out or loadcallback fail
            DLP_LOG_ERROR(LABEL, "Dlp Permission load sa timeout");
            return;
        }
    }
    if (GetRemoteObject() == nullptr) {
        DLP_LOG_ERROR(LABEL, "RemoteObject is null");
        return;
    }
    serviceDeathObserver_ = new (std::nothrow) DlpPermissionDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        GetRemoteObject()->AddDeathRecipient(serviceDeathObserver_);
    }
}

void DlpPermissionClient::OnRemoteDiedHandle()
{
    DLP_LOG_ERROR(LABEL, "Remote service died");
    SetRemoteObject(nullptr);
    std::unique_lock<std::mutex> lock(cvLock_);
    readyFlag_ = false;
}

void DlpPermissionClient::SetRemoteObject(const sptr<IRemoteObject>& remoteObject)
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    remoteObject_ = remoteObject;
}

sptr<IRemoteObject> DlpPermissionClient::GetRemoteObject()
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    return remoteObject_;
}

sptr<IDlpPermissionService> DlpPermissionClient::GetProxy()
{
    {
        std::unique_lock<std::mutex> lock(proxyMutex_);
        if (GetRemoteObject() == nullptr) {
            InitProxy();
        }
    }
    sptr<IDlpPermissionService> proxy = iface_cast<IDlpPermissionService>(GetRemoteObject());
    if (proxy == nullptr) {
        DLP_LOG_ERROR(LABEL, "iface_cast get null");
    }
    return proxy;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
