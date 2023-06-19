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

#include "open_dlp_file_callback_info_parcel.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "OpenDlpFileCallbackInfoParcel"};
}

bool OpenDlpFileCallbackInfoParcel::Marshalling(Parcel& out) const
{
    if (!(out.WriteString(this->fileInfo.uri))) {
        DLP_LOG_ERROR(LABEL, "Write uri fail");
        return false;
    }
    if (!(out.WriteUint64(this->fileInfo.timeStamp))) {
        DLP_LOG_ERROR(LABEL, "Write timeStamp fail");
        return false;
    }
    return true;
}

OpenDlpFileCallbackInfoParcel* OpenDlpFileCallbackInfoParcel::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) OpenDlpFileCallbackInfoParcel();
    if (parcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!(in.ReadString(parcel->fileInfo.uri))) {
        DLP_LOG_ERROR(LABEL, "Read uri fail");
        delete parcel;
        parcel = nullptr;
        return nullptr;
    }
    if (!(in.ReadUint64(parcel->fileInfo.timeStamp))) {
        DLP_LOG_ERROR(LABEL, "Read timeStamp fail");
        delete parcel;
        parcel = nullptr;
        return nullptr;
    }
    return parcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
