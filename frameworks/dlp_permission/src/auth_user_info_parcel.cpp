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

#include "auth_user_info_parcel.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionParcel"};
}
bool AuthUserInfoParcel::Marshalling(Parcel& out) const
{
    if (!(out.WriteString(this->authUserInfo_.authAccount))) {
        DLP_LOG_ERROR(LABEL, "Write string fail");
        return false;
    }
    if (!(out.WriteUint8(this->authUserInfo_.authPerm))) {
        DLP_LOG_ERROR(LABEL, "Write uint8 fail");
        return false;
    }
    if (!(out.WriteUint64(this->authUserInfo_.permExpiryTime))) {
        DLP_LOG_ERROR(LABEL, "Write uint64 fail");
        return false;
    }
    if (!(out.WriteUint8(this->authUserInfo_.authAccountType))) {
        DLP_LOG_ERROR(LABEL, "Write uint8 fail");
        return false;
    }
    return true;
}

AuthUserInfoParcel* AuthUserInfoParcel::Unmarshalling(Parcel& in)
{
    auto authUserInfoParcel = new (std::nothrow) AuthUserInfoParcel();
    if (authUserInfoParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }

    if (!(in.ReadString(authUserInfoParcel->authUserInfo_.authAccount))) {
        DLP_LOG_ERROR(LABEL, "Read string fail");
        delete authUserInfoParcel;
        authUserInfoParcel = nullptr;
        return nullptr;
    }
    uint8_t res;
    if (!(in.ReadUint8(res))) {
        DLP_LOG_ERROR(LABEL, "Read uint8 fail");
        delete authUserInfoParcel;
        authUserInfoParcel = nullptr;
        return nullptr;
    }
    authUserInfoParcel->authUserInfo_.authPerm = static_cast<AuthPermType>(res);
    if (!(in.ReadUint64(authUserInfoParcel->authUserInfo_.permExpiryTime))) {
        DLP_LOG_ERROR(LABEL, "Read uint64 fail");
        delete authUserInfoParcel;
        authUserInfoParcel = nullptr;
        return nullptr;
    }

    if (!(in.ReadUint8(res))) {
        DLP_LOG_ERROR(LABEL, "Read uint8 fail");
        delete authUserInfoParcel;
        authUserInfoParcel = nullptr;
        return nullptr;
    }
    authUserInfoParcel->authUserInfo_.authAccountType = static_cast<DlpAccountType>(res);

    return authUserInfoParcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
