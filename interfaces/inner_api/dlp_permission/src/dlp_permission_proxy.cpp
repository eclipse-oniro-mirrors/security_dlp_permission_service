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
}

DlpPermissionProxy::DlpPermissionProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IDlpPermissionService>(impl)
{}

DlpPermissionProxy::~DlpPermissionProxy()
{}

int32_t DlpPermissionProxy::GenerateDlpCertificate(
    const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback)
{
    MessageParcel data;
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
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GENERATE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, sptr<IDlpPermissionCallback>& callback)
{
    MessageParcel data;
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
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::PARSE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
    }
    return res;
}

int32_t DlpPermissionProxy::InstallDlpSandbox(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex)
{
    MessageParcel data;
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

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::INSTALL_DLP_SANDBOX), data, reply, option);
    if (requestResult != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Request fail, result: %{public}d", requestResult);
        return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
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
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
