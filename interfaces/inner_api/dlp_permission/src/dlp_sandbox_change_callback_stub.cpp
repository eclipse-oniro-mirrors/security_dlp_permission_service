/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_callback_info_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
    "DlpSandboxChangeCallbackStub" };
}

int32_t DlpSandboxChangeCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IDlpSandboxStateChangeCallback::GetDescriptor()) {
        DLP_LOG_ERROR(LABEL, "get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }

    int32_t msgCode = static_cast<int32_t>(code);
    if (msgCode == IDlpSandboxStateChangeCallback::DLP_SANDBOX_STATE_CHANGE) {
        DlpSandboxCallbackInfo result;
        sptr<DlpSandboxCallbackInfoParcel> resultSptr = data.ReadParcelable<DlpSandboxCallbackInfoParcel>();
        if (resultSptr == nullptr) {
            DLP_LOG_ERROR(LABEL, "ReadParcelable fail");
            return DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL;
        }

        DlpSandboxStateChangeCallback(resultSptr->changeInfo);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return DLP_OK;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
