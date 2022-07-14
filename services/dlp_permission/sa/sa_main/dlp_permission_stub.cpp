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

#include "dlp_permission_stub.h"
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionStub"};
const std::string PERMISSION_ACCESS_DLP_FILE = "ohos.permission.ACCESS_DLP_FILE";
}  // namespace

static bool CheckPermission(const std::string& permission)
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingToken, permission);
    if (res == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        DLP_LOG_INFO(LABEL, "check permission %{public}s pass", permission.c_str());
        return true;
    }
    DLP_LOG_ERROR(LABEL, "check permission %{public}s fail", permission.c_str());
    return false;
}

int32_t DlpPermissionStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DLP_LOG_INFO(LABEL, "Called, code: %{public}u", code);

    std::u16string descripter = DlpPermissionStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        DLP_LOG_ERROR(LABEL, "OnRemoteRequest failed, descriptor is not matched");
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        } else {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GenerateDlpCertificateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    sptr<DlpPolicyParcel> policyParcel = data.ReadParcelable<DlpPolicyParcel>();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read parcel fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->GenerateDlpCertificate(policyParcel, callback);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::ParseDlpCertificateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::vector<uint8_t> cert;
    if (!data.ReadUInt8Vector(&cert)) {
        DLP_LOG_ERROR(LABEL, "Read uint8 vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->ParseDlpCertificate(cert, callback);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::InstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Read string fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    uint32_t type;
    if (!data.ReadUint32(type)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    AuthPermType permType = static_cast<AuthPermType>(type);

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t appIndex;
    int32_t res = this->InstallDlpSandbox(bundleName, permType, userId, appIndex);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::UninstallDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    if (!CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        return DLP_SERVICE_ERROR_PERMISSION_DENY;
    }

    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Read string fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t appIndex;
    if (!data.ReadInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t res = this->UninstallDlpSandbox(bundleName, appIndex, userId);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

DlpPermissionStub::DlpPermissionStub()
{
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GENERATE_DLP_CERTIFICATE)] =
        &DlpPermissionStub::GenerateDlpCertificateInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::PARSE_DLP_CERTIFICATE)] =
        &DlpPermissionStub::ParseDlpCertificateInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::INSTALL_DLP_SANDBOX)] =
        &DlpPermissionStub::InstallDlpSandboxInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::UNINSTALL_DLP_SANDBOX)] =
        &DlpPermissionStub::UninstallDlpSandboxInner;
}

DlpPermissionStub::~DlpPermissionStub()
{
    requestFuncMap_.clear();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
