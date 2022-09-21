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
#include "dlp_dfx_define.h"
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
        DLP_LOG_INFO(LABEL, "Check permission %{public}s pass", permission.c_str());
        return true;
    }

    HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::DLP, "DLP_PERMISSION_REPORT",
        HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", DLP_PERMISSION_VERIFY_ERROR,
        "CALLER_TOKENID", callingToken);

    DLP_LOG_ERROR(LABEL, "Check permission %{public}s fail", permission.c_str());
    return false;
}

static bool IsSaCall()
{
    Security::AccessToken::AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::TypeATokenTypeEnum res = Security::AccessToken::AccessTokenKit::GetTokenType(callingToken);
    return (res == Security::AccessToken::TOKEN_NATIVE);
}

int32_t DlpPermissionStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    DLP_LOG_INFO(LABEL, "Called, code: 0x%{public}x, pid: %{public}d, uid: %{public}d", code,
        IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid());

    std::u16string descripter = DlpPermissionStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        DLP_LOG_ERROR(LABEL, "Deal remote request fail, descriptor is not matched");
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
        DLP_LOG_ERROR(LABEL, "Read dlp policy parcel fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read generate cert callback object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Iface cast generate cert callback fail");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->GenerateDlpCertificate(policyParcel, callback);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write generate cert result fail");
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
        DLP_LOG_ERROR(LABEL, "Read cert fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read parse cert callback object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(obj);
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Iface cast parse cert callback fail");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    int32_t res = this->ParseDlpCertificate(cert, callback);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write parse cert result fail");
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
        DLP_LOG_ERROR(LABEL, "Read bundle name fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    uint32_t type;
    if (!data.ReadUint32(type)) {
        DLP_LOG_ERROR(LABEL, "Read auth perm type fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    AuthPermType permType = static_cast<AuthPermType>(type);

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read user id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t appIndex;
    int32_t res = this->InstallDlpSandbox(bundleName, permType, userId, appIndex);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write install sandbox result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox index fail");
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
        DLP_LOG_ERROR(LABEL, "Read bundle name fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t appIndex;
    if (!data.ReadInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Read sandbox index fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Read user id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    int32_t res = this->UninstallDlpSandbox(bundleName, appIndex, userId);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write uninstall sandbox result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetSandboxExternalAuthorizationInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSaCall() && !CheckPermission(PERMISSION_ACCESS_DLP_FILE)) {
        DLP_LOG_ERROR(LABEL, "Caller is not SA or has no ACCESS_DLP_FILE permission");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t sandboxUid;
    if (!data.ReadInt32(sandboxUid)) {
        DLP_LOG_ERROR(LABEL, "Read sandbox uid fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    std::unique_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read want fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    SandBoxExternalAuthorType authType;
    int32_t res = this->GetSandboxExternalAuthorization(sandboxUid, *want, authType);
    if (res != DLP_OK) {
        return res;
    }

    if (!reply.WriteInt32(authType)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox external auth type fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::QueryDlpFileCopyableByTokenIdInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        DLP_LOG_ERROR(LABEL, "Read token id fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    bool copyable = false;
    int32_t res = this->QueryDlpFileCopyableByTokenId(copyable, tokenId);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write copyalbe query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(copyable)) {
        DLP_LOG_ERROR(LABEL, "Write copyalbe fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::QueryDlpFileAccessInner(MessageParcel& data, MessageParcel& reply)
{
    AuthPermType permType = DEFAULT_PERM;
    int32_t res = this->QueryDlpFileAccess(permType);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write dlp file access query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteUint32(permType)) {
        DLP_LOG_ERROR(LABEL, "Write file access fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::IsInDlpSandboxInner(MessageParcel& data, MessageParcel& reply)
{
    bool inSandbox = false;
    int32_t res = this->IsInDlpSandbox(inSandbox);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.WriteBool(inSandbox)) {
        DLP_LOG_ERROR(LABEL, "Write sandbox flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpPermissionStub::GetDlpSupportFileTypeInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> supportFileType;
    int32_t res = this->GetDlpSupportFileType(supportFileType);
    if (!reply.WriteInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Write support dlp file type query result fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    size_t listNum = supportFileType.size();
    if (!reply.WriteUint32(listNum)) {
        DLP_LOG_ERROR(LABEL, "Write support dlp file type list num fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    for (const auto& iter : supportFileType) {
        if (!reply.WriteString(iter)) {
            DLP_LOG_ERROR(LABEL, "Write support dlp file type string fail");
            return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
        }
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
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_SANDBOX_EXTERNAL_AUTH)] =
        &DlpPermissionStub::GetSandboxExternalAuthorizationInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::QUERY_DLP_FILE_ACCESS_BY_TOKEN_ID)] =
        &DlpPermissionStub::QueryDlpFileCopyableByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::QUERY_DLP_FILE_ACCESS)] =
        &DlpPermissionStub::QueryDlpFileAccessInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::IS_IN_DLP_SANDBOX)] =
        &DlpPermissionStub::IsInDlpSandboxInner;
    requestFuncMap_[static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_DLP_SUPPORT_FILE_TYPE)] =
        &DlpPermissionStub::GetDlpSupportFileTypeInner;
}

DlpPermissionStub::~DlpPermissionStub()
{
    requestFuncMap_.clear();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
