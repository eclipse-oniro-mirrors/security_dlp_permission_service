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

#include "dlp_policy_parcel.h"
#include "dlp_permission_log.h"
#include "dlp_policy.h"
#include "securec.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionParcel"};
}
bool DlpPolicyParcel::Marshalling(Parcel& out) const
{
    const std::vector<AuthUserInfo>& userList = this->policyParams_.authUsers_;
    uint32_t listSize = userList.size();
    if (!(out.WriteUint32(listSize))) {
        DLP_LOG_ERROR(LABEL, "Write uint32 fail");
        return false;
    }

    for (uint32_t i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = new (std::nothrow) AuthUserInfoParcel();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return false;
        }
        authUserInfoParcel->authUserInfo_ = userList[i];
        if (!(out.WriteParcelable(authUserInfoParcel))) {
            DLP_LOG_ERROR(LABEL, "Write parcel fail");
            return false;
        }
    }
    if (!(out.WriteString(this->policyParams_.ownerAccount_))) {
        DLP_LOG_ERROR(LABEL, "Write string fail");
    }
    if (!(out.WriteUint8(this->policyParams_.ownerAccountType_))) {
        DLP_LOG_ERROR(LABEL, "Write uint8 fail");
    }
    if (!(out.WriteUint32(this->policyParams_.GetAeskeyLen()))) {
        DLP_LOG_ERROR(LABEL, "Write uint32 fail");
    }
    if (!(out.WriteBuffer(this->policyParams_.GetAeskey(), this->policyParams_.GetAeskeyLen()))) {
        DLP_LOG_ERROR(LABEL, "Write buffer fail");
    }
    if (!(out.WriteUint32(this->policyParams_.GetIvLen()))) {
        DLP_LOG_ERROR(LABEL, "Write uint32 fail");
    }
    if (!(out.WriteBuffer(this->policyParams_.GetIv(), this->policyParams_.GetIvLen()))) {
        DLP_LOG_ERROR(LABEL, "Write buffer fail");
    }

    return true;
}

static bool ReadAesParam(PermissionPolicy& policy, Parcel& in)
{
    uint32_t len;
    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 fail");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "key param invalid");
        return false;
    }
    const uint8_t* key = in.ReadUnpadBuffer(len);
    if (key == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read buffer fail");
        return false;
    }
    policy.SetAeskey(key, len);

    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 fail");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "iv param invalid");
        return false;
    }
    const uint8_t* iv = in.ReadUnpadBuffer(len);
    if (iv == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read buffer fail");
        return false;
    }
    policy.SetIv(iv, len);
    return true;
}

static bool ReadParcel(Parcel& in, DlpPolicyParcel* policyParcel)
{
    uint32_t listSize;
    if (!in.ReadUint32(listSize)) {
        DLP_LOG_ERROR(LABEL, "Read uint32 fail");
        return false;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = in.ReadParcelable<AuthUserInfoParcel>();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "Read parcel fail");
            return false;
        }
        policyParcel->policyParams_.authUsers_.emplace_back(authUserInfoParcel->authUserInfo_);
    }
    if (!(in.ReadString(policyParcel->policyParams_.ownerAccount_))) {
        DLP_LOG_ERROR(LABEL, "Read string fail");
        return false;
    }
    uint8_t res = 0;
    if (!(in.ReadUint8(res))) {
        DLP_LOG_ERROR(LABEL, "Read uint8 fail");
        return false;
    }
    policyParcel->policyParams_.ownerAccountType_ = static_cast<DlpAccountType>(res);
    ReadAesParam(policyParcel->policyParams_, in);
    return true;
}

DlpPolicyParcel* DlpPolicyParcel::Unmarshalling(Parcel& in)
{
    DlpPolicyParcel* policyParcel = new (std::nothrow) DlpPolicyParcel();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }

    if (!ReadParcel(in, policyParcel)) {
        delete policyParcel;
        policyParcel = nullptr;
    }
    return policyParcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
