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

#include "dlp_sandbox_callback_info_parcel.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "DlpSandboxCallbackInfoParcel" };
}

bool DlpSandboxCallbackInfoParcel::Marshalling(Parcel &out) const
{
    if (!(out.WriteInt32(this->changeInfo.appIndex))) {
        DLP_LOG_ERROR(LABEL, "Write appIndex fail");
        return false;
    }
    if (!(out.WriteString(this->changeInfo.bundleName))) {
        DLP_LOG_ERROR(LABEL, "Write bundleName fail");
        return false;
    }
    return true;
}

DlpSandboxCallbackInfoParcel *DlpSandboxCallbackInfoParcel::Unmarshalling(Parcel &in)
{
    auto *permissionStateParcel = new (std::nothrow) DlpSandboxCallbackInfoParcel();
    if (permissionStateParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!(in.ReadInt32(permissionStateParcel->changeInfo.appIndex))) {
        DLP_LOG_ERROR(LABEL, "Read appIndex fail");
        delete permissionStateParcel;
        permissionStateParcel = nullptr;
        return nullptr;
    }
    if (!(in.ReadString(permissionStateParcel->changeInfo.bundleName))) {
        DLP_LOG_ERROR(LABEL, "Read bundleName fail");
        delete permissionStateParcel;
        permissionStateParcel = nullptr;
        return nullptr;
    }
    return permissionStateParcel;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
