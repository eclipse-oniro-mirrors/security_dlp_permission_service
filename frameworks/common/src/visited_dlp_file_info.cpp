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

#include "visited_dlp_file_info.h"
#include "dlp_permission_log.h"
#include "i_json_operator.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "VisitedDLPFileInfo" };
}

VisitedDLPFileInfo::VisitedDLPFileInfo()
{
    visitTimestamp = -1;
    docUri = "";
}

bool VisitedDLPFileInfo::Marshalling(Parcel& out) const
{
    if (!(out.WriteInt64(this->visitTimestamp))) {
        DLP_LOG_ERROR(LABEL, "Write visitTimestamp fail");
        return false;
    }
    if (!(out.WriteString(this->docUri))) {
        DLP_LOG_ERROR(LABEL, "Write docUri fail");
        return false;
    }
    return true;
}

VisitedDLPFileInfo* VisitedDLPFileInfo::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) VisitedDLPFileInfo();
    if (parcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!(in.ReadInt64(parcel->visitTimestamp))) {
        DLP_LOG_ERROR(LABEL, "Read visitTimestamp fail");
        delete parcel;
        parcel = nullptr;
        return nullptr;
    }
    if (!(in.ReadString(parcel->docUri))) {
        DLP_LOG_ERROR(LABEL, "Read docUri fail");
        delete parcel;
        parcel = nullptr;
        return nullptr;
    }
    return parcel;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
