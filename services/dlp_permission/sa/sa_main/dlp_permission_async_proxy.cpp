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

#include "dlp_permission_async_proxy.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_policy_parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionAsyncProxy"};
}

void DlpPermissionAsyncProxy::onGenerateDlpCertificate(const int32_t result, const std::vector<uint8_t>& cert)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionAsyncProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        DLP_LOG_ERROR(LABEL, "Write int32 fail");
        return;
    }
    if (!data.WriteUInt8Vector(cert)) {
        DLP_LOG_ERROR(LABEL, "Write uint8 vector fail");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionCallback::InterfaceCode::ON_GENERATE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != NO_ERROR) {
        DLP_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", requestResult);
        return;
    }

    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return;
    }
    DLP_LOG_DEBUG(LABEL, "Res = %{public}d", res);
}

void DlpPermissionAsyncProxy::onParseDlpCertificate(const PermissionPolicy& result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(DlpPermissionAsyncProxy::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor failed");
        return;
    }

    DlpPolicyParcel policyParcel;
    policyParcel.policyParams_ = result;

    if (!data.WriteParcelable(&policyParcel)) {
        DLP_LOG_ERROR(LABEL, "Write parcel fail");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpPermissionCallback::InterfaceCode::ON_PARSE_DLP_CERTIFICATE), data, reply, option);
    if (requestResult != NO_ERROR) {
        DLP_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", requestResult);
        return;
    }

    int32_t res;
    if (!reply.ReadInt32(res)) {
        DLP_LOG_ERROR(LABEL, "Read int32 fail");
        return;
    }
    DLP_LOG_DEBUG(LABEL, "Res = %{public}d", res);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
