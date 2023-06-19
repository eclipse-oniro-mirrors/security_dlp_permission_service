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

#include "dlp_sandbox_change_callback_death_recipient.h"
#include "dlp_sandbox_change_callback_manager.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
    "DlpSandboxChangeCallbackDeathRecipient" };
}

void DlpSandboxChangeCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        DLP_LOG_ERROR(LABEL, "remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        DLP_LOG_ERROR(LABEL, "object is nullptr");
        return;
    }
    DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(object);
    DLP_LOG_INFO(LABEL, "end");
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
