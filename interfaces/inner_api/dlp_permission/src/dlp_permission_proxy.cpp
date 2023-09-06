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

#include "dlp_permission_proxy.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionProxy"};
static const uint32_t MAX_SUPPORT_FILE_TYPE_NUM = 1024;
static const uint32_t MAX_RETENTION_SIZE = 1024;
}

DlpPermissionProxy::DlpPermissionProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IDlpPermissionService>(impl)
{}

DlpPermissionProxy::~DlpPermissionProxy()
{}

int32_t DlpPermissionProxy::GenerateDlpCertificate(
    const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteParcelable(policyParcel)) {
        DLP_LOG_ERROR(LABEL, "Write parcel fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        DLP_LOG_ERROR(LABEL, "Write object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GENERATE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, uint32_t flag, sptr<IDlpPermissionCallback>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteUint32(flag)) {
        DLP_LOG_ERROR(LABEL, "Write uint32 flag fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteUInt8Vector(cert)) {
        DLP_LOG_ERROR(LABEL, "Write uint8 vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        DLP_LOG_ERROR(LABEL, "Write object fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }

    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::PARSE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }

    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::InstallDlpSandbox(const std::string& bundleName, AuthPermType permType, int32_t userId,
    int32_t& appIndex, const std::string& uri)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Write string fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteUint32(permType)) {
        DLP_LOG_ERROR(LABEL, "Write uint32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteString(uri)) {
        DLP_LOG_ERROR(LABEL, "Write string fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::INSTALL_DLP_SANDBOX), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!reply.ReadInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Write string fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteInt32(appIndex)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteInt32(userId)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::UNINSTALL_DLP_SANDBOX), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::GetSandboxExternalAuthorization(int sandboxUid,
    const AAFwk::Want& want, SandBoxExternalAuthorType& authType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteInt32(sandboxUid)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteParcelable(&want)) {
        DLP_LOG_ERROR(LABEL, "Write want fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_SANDBOX_EXTERNAL_AUTH), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (res < DENY_START_ABILITY || res > ALLOW_START_ABILITY) {
        DLP_LOG_ERROR(LABEL, "Read authType result value error");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    authType = static_cast<SandBoxExternalAuthorType>(res);
    return DLP_OK;
}

int32_t DlpPermissionProxy::QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteUint32(tokenId)) {
        DLP_LOG_ERROR(LABEL, "Write uint32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::QUERY_DLP_FILE_ACCESS_BY_TOKEN_ID), data, reply,
        option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.ReadBool(copyable)) {
        DLP_LOG_ERROR(LABEL, "Read bool fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::QueryDlpFileAccess(DLPPermissionInfoParcel& permInfoParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::QUERY_DLP_FILE_ACCESS), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    std::unique_ptr<DLPPermissionInfoParcel> info(reply.ReadParcelable<DLPPermissionInfoParcel>());
    if (info == nullptr) {
        DLP_LOG_ERROR(LABEL, "ReadParcelable fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    permInfoParcel = *info;
    return res;
}

int32_t DlpPermissionProxy::IsInDlpSandbox(bool& inSandbox)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::IS_IN_DLP_SANDBOX), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.ReadBool(inSandbox)) {
        DLP_LOG_ERROR(LABEL, "Read bool fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::GetDlpSupportFileType(std::vector<std::string>& supportFileType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_DLP_SUPPORT_FILE_TYPE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    uint32_t listNum;
    if (!reply.ReadUint32(listNum)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (listNum > MAX_SUPPORT_FILE_TYPE_NUM) {
        DLP_LOG_ERROR(LABEL, "listNum larger than 1024");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    for (uint32_t i = 0; i < listNum; i++) {
        std::string fileType;
        if (!reply.ReadString(fileType)) {
            DLP_LOG_ERROR(LABEL, "Read string fail");
            return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
        }
        supportFileType.emplace_back(fileType);
    }

    return res;
}

int32_t DlpPermissionProxy::RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!data.WriteRemoteObject(callback)) {
        DLP_LOG_ERROR(LABEL, "Failed to write remote object.");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::REGISTER_DLP_SANDBOX_CHANGE_CALLBACK), data, reply,
        option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        DLP_LOG_ERROR(LABEL, "ReadInt32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return result;
}

int32_t DlpPermissionProxy::UnRegisterDlpSandboxChangeCallback(bool &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK), data,
        reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return DLP_CALLBACK_SA_WORK_ABNORMAL;
    }

    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "ReadInt32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.ReadBool(result)) {
        DLP_LOG_ERROR(LABEL, "Read bool fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::GetDlpGatheringPolicy(bool& isGathering)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_DLP_GATHERING_POLICY), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (!reply.ReadBool(isGathering)) {
        DLP_LOG_ERROR(LABEL, "Read bool fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::SetRetentionState(const std::vector<std::string>& docUriVec)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteStringVector(docUriVec)) {
        DLP_LOG_ERROR(LABEL, "Write string vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::SET_RETENTION_STATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::SetNonRetentionState(const std::vector<std::string>& docUriVec)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteStringVector(docUriVec)) {
        DLP_LOG_ERROR(LABEL, "Write string vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::SET_NOT_RETENTION_STATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    if (!data.WriteString(bundleName)) {
        DLP_LOG_ERROR(LABEL, "Write string vector fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GET_RETETNTION_SANDBOX_LIST), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return requestResult;
    }

    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    uint32_t size;
    if (!reply.ReadUint32(size)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 size fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    if (size > MAX_RETENTION_SIZE) {
        DLP_LOG_ERROR(LABEL, "size larger than 1024");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    for (uint32_t i = 0; i < size; i++) {
        std::unique_ptr<RetentionSandBoxInfo> info(reply.ReadParcelable<RetentionSandBoxInfo>());
        if (info != nullptr) {
            retentionSandBoxInfoVec.push_back(*info);
        }
    }
    return res;
}

int32_t DlpPermissionProxy::ClearUnreservedSandbox()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_SERVICE_NOT_EXIST;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::CLEAR_UNRESERVED_SANDBOX), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
    }
    return requestResult;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
