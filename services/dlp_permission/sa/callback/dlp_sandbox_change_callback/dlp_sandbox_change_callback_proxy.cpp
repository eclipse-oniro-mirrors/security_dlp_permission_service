/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlp_sandbox_change_callback_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_callback_info_parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "DlpSandboxChangeCallbackProxy" };
}

DlpSandboxChangeCallbackProxy::DlpSandboxChangeCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDlpSandboxStateChangeCallback>(impl)
{}

DlpSandboxChangeCallbackProxy::~DlpSandboxChangeCallbackProxy() {}

void DlpSandboxChangeCallbackProxy::DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDlpSandboxStateChangeCallback::GetDescriptor())) {
        DLP_LOG_ERROR(LABEL, "Write descriptor fail");
        return;
    }

    DlpSandboxCallbackInfoParcel resultParcel;
    resultParcel.changeInfo = result;
    if (!data.WriteParcelable(&resultParcel)) {
        DLP_LOG_ERROR(LABEL, "Failed to WriteParcelable(result)");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IDlpSandboxStateChangeCallback::DLP_SANDBOX_STATE_CHANGE), data, reply, option);
    if (requestResult != NO_ERROR) {
        DLP_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    DLP_LOG_DEBUG(LABEL, "SendRequest success");
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
