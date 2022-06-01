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
#include "dlp_policy_helper.h"
#include "securec.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionParcel"};
}
bool DlpPolicyParcel::Marshalling(Parcel& out) const
{
    const std::vector<AuthUserInfo>& userList = this->policyParams_.authUsers;
    int32_t listSize = (int32_t)userList.size();
    if (!(out.WriteInt32(listSize))) {
        DLP_LOG_ERROR(LABEL, "WriteInt32 fail");
        return false;
    }

    for (int i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = new (std::nothrow) AuthUserInfoParcel();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return false;
        }
        authUserInfoParcel->authUserInfo_ = userList[i];
        if (!(out.WriteParcelable(authUserInfoParcel))) {
            DLP_LOG_ERROR(LABEL, "WriteParcelable fail");
            return false;
        }
    }
    if (!(out.WriteString(this->policyParams_.ownerAccount))) {
        DLP_LOG_ERROR(LABEL, "WriteString fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.aeskeyLen))) {
        DLP_LOG_ERROR(LABEL, "WriteUint32 fail");
        return false;
    }
    if (!(out.WriteBuffer(this->policyParams_.aeskey, this->policyParams_.aeskeyLen))) {
        DLP_LOG_ERROR(LABEL, "WriteBuffer fail");
        return false;
    }
    if (!(out.WriteUint32(this->policyParams_.ivLen))) {
        DLP_LOG_ERROR(LABEL, "WriteUint32 fail");
        return false;
    }
    if (!(out.WriteBuffer(this->policyParams_.iv, this->policyParams_.ivLen))) {
        DLP_LOG_ERROR(LABEL, "WriteBuffer fail");
        return false;
    }

    return true;
}

static bool ReadDlpBuff(uint8_t** buff, uint32_t& len, Parcel& in)
{
    if (!in.ReadUint32(len)) {
        DLP_LOG_ERROR(LABEL, "ReadUint32 fail");
        return false;
    }
    const uint8_t* data = in.ReadUnpadBuffer(len);
    if (data == nullptr) {
        DLP_LOG_ERROR(LABEL, "ReadUnpadBuffer fail");
        return false;
    }
    *buff = new (std::nothrow) uint8_t[len];
    if (*buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return false;
    }
    if (memcpy_s(*buff, len, data, len) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
        delete[] * buff;
        *buff = nullptr;
        return false;
    }
    return true;
}

DlpPolicyParcel* DlpPolicyParcel::Unmarshalling(Parcel& in)
{
    DlpPolicyParcel* policyParcel = new (std::nothrow) DlpPolicyParcel();
    if (policyParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }

    int listSize;
    if (!in.ReadInt32(listSize)) {
        DLP_LOG_ERROR(LABEL, "ReadInt32 fail");
        delete policyParcel;
        policyParcel = nullptr;
        return nullptr;
    }
    for (int i = 0; i < listSize; i++) {
        sptr<AuthUserInfoParcel> authUserInfoParcel = in.ReadParcelable<AuthUserInfoParcel>();
        if (authUserInfoParcel == nullptr) {
            DLP_LOG_ERROR(LABEL, "AuthUserInfoParcel is null");
            delete policyParcel;
            policyParcel = nullptr;
            return nullptr;
        }
        policyParcel->policyParams_.authUsers.emplace_back(authUserInfoParcel->authUserInfo_);
    }
    if (!(in.ReadString(policyParcel->policyParams_.ownerAccount))) {
        DLP_LOG_ERROR(LABEL, "ReadString fail");
        delete policyParcel;
        policyParcel = nullptr;
        return nullptr;
    }
    if (!(ReadDlpBuff(&policyParcel->policyParams_.aeskey, policyParcel->policyParams_.aeskeyLen, in))) {
        delete policyParcel;
        policyParcel = nullptr;
        return nullptr;
    }
    if (!(ReadDlpBuff(&policyParcel->policyParams_.iv, policyParcel->policyParams_.ivLen, in))) {
        policyParcel->FreeMem();
        delete policyParcel;
        policyParcel = nullptr;
        return nullptr;
    }
    return policyParcel;
}

void DlpPolicyParcel::FreeMem()
{
    FreePermissionPolicyMem(policyParams_);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
