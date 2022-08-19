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

#include "dlp_policy.h"
#include <chrono>
#include <set>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPolicyCheck"};
const uint32_t MAX_ACCOUNT_SIZE = 1024;
const uint32_t MAX_ACCOUNT_NUM = 100;
const std::set<uint32_t> VALID_AESPARAM_LEN = {16, 24, 32};
}  // namespace

static bool CheckAesParam(const uint8_t* buff, uint32_t len)
{
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "Param is null");
        return false;
    }
    if (!CheckAesParamLen(len)) {
        DLP_LOG_ERROR(LABEL, "Len is invalid, %{public}d", len);
        return false;
    }
    return true;
}

static bool CheckAccount(const std::string& account)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}s", account.c_str());
    if (account.empty() || account.size() > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Account is invalid");
        return false;
    }
    return true;
}

static bool CheckPerm(uint32_t perm)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}d", perm);
    if (perm <= 0 || perm >= DEFAULT_PERM) {
        DLP_LOG_ERROR(LABEL, "Perm is invalid");
        return false;
    }
    return true;
}

static bool CheckTime(uint64_t time)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}lu", time);
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    if (time < curTime) {
        DLP_LOG_ERROR(LABEL, "Perm expiry time is invalid");
        return false;
    }
    return true;
}

static bool CheckAuthUserInfo(const AuthUserInfo& info)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    return (CheckAccount(info.authAccount) && CheckPerm(info.authPerm) && CheckTime(info.permExpiryTime) &&
            CheckAccountType(info.authAccountType));
}

static bool CheckAuthUserInfoList(const std::vector<AuthUserInfo>& authUsers_)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}zu", authUsers_.size());
    if (authUsers_.size() <= MAX_ACCOUNT_NUM) {
        for (auto iter : authUsers_) {
            if (!CheckAuthUserInfo(iter)) {
                return false;
            }
        }
        return true;
    }
    DLP_LOG_ERROR(LABEL, "Auth users size is invalid");
    return false;
}

static void FreeUint8Buffer(uint8_t** buff, uint32_t& buffLen)
{
    if (*buff != nullptr) {
        memset_s(*buff, buffLen, 0, buffLen);
        delete[] *buff;
        *buff = nullptr;
    }
    buffLen = 0;
}

void PermissionPolicy::FreePermissionPolicyMem()
{
    FreeUint8Buffer(&aeskey_, aeskeyLen_);
    FreeUint8Buffer(&iv_, ivLen_);
    ownerAccount_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_.clear();
}

PermissionPolicy::PermissionPolicy()
{
    DLP_LOG_DEBUG(LABEL, "Called");
    ownerAccount_ = "";
    ownerAccountType_ = INVALID_ACCOUNT;
    authUsers_ = {};
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
}

PermissionPolicy::PermissionPolicy(const DlpProperty& property)
{
    DLP_LOG_DEBUG(LABEL, "called");
    ownerAccount_ = property.ownerAccount;
    ownerAccountType_ = property.ownerAccountType;
    authUsers_ = property.authUsers;
    aeskey_ = nullptr;
    aeskeyLen_ = 0;
    iv_ = nullptr;
    ivLen_ = 0;
}

PermissionPolicy::~PermissionPolicy()
{
    DLP_LOG_DEBUG(LABEL, "Called");
    FreePermissionPolicyMem();
}

bool PermissionPolicy::IsValid() const
{
    return (CheckAccount(this->ownerAccount_) && CheckAccountType(this->ownerAccountType_) &&
            CheckAesParam(this->aeskey_, this->aeskeyLen_) && CheckAesParam(this->iv_, this->ivLen_) &&
            CheckAuthUserInfoList(this->authUsers_));
}

void PermissionPolicy::SetAeskey(const uint8_t* key, uint32_t keyLen)
{
    if (key == nullptr) {
        DLP_LOG_INFO(LABEL, "free key!");
        FreeUint8Buffer(&aeskey_, aeskeyLen_);
        return;
    }
    if (!CheckAesParam(key, keyLen)) {
        DLP_LOG_ERROR(LABEL, "param invalid");
        return;
    }
    FreeUint8Buffer(&aeskey_, aeskeyLen_);
    aeskey_ = new (std::nothrow) uint8_t[keyLen];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }
    aeskeyLen_ = keyLen;
    if (memcpy_s(aeskey_, aeskeyLen_, key, keyLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy fail");
        FreeUint8Buffer(&aeskey_, aeskeyLen_);
        return;
    }
}

uint8_t* PermissionPolicy::GetAeskey() const
{
    return aeskey_;
}

uint32_t PermissionPolicy::GetAeskeyLen() const
{
    return aeskeyLen_;
}

void PermissionPolicy::SetIv(const uint8_t* iv, uint32_t ivLen)
{
    if (iv == nullptr) {
        DLP_LOG_INFO(LABEL, "free iv!");
        FreeUint8Buffer(&iv_, ivLen_);
        return;
    }
    if (!CheckAesParam(iv, ivLen)) {
        DLP_LOG_ERROR(LABEL, "param invalid");
        return;
    }
    FreeUint8Buffer(&iv_, ivLen_);
    iv_ = new (std::nothrow) uint8_t[ivLen];
    if (iv_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }
    ivLen_ = ivLen;
    if (memcpy_s(iv_, ivLen_, iv, ivLen) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy fail");
        FreeUint8Buffer(&iv_, ivLen_);
        return;
    }
}

uint8_t* PermissionPolicy::GetIv() const
{
    return iv_;
}

uint32_t PermissionPolicy::GetIvLen() const
{
    return ivLen_;
}

void PermissionPolicy::CopyPermissionPolicy(const PermissionPolicy& srcPolicy)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (!srcPolicy.IsValid()) {
        DLP_LOG_ERROR(LABEL, "dest policy is invalid");
        return;
    }
    ownerAccount_ = srcPolicy.ownerAccount_;
    ownerAccountType_ = srcPolicy.ownerAccountType_;
    authUsers_ = srcPolicy.authUsers_;
    aeskeyLen_ = srcPolicy.aeskeyLen_;
    aeskey_ = new (std::nothrow) uint8_t[aeskeyLen_];
    if (aeskey_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }
    if (memcpy_s(aeskey_, aeskeyLen_, srcPolicy.aeskey_, srcPolicy.aeskeyLen_) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy fail");
        FreePermissionPolicyMem();
        return;
    }
    ivLen_ = srcPolicy.ivLen_;
    iv_ = new (std::nothrow) uint8_t[ivLen_];
    if (iv_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        FreePermissionPolicyMem();
        return;
    }
    if (memcpy_s(iv_, ivLen_, srcPolicy.iv_, srcPolicy.ivLen_) != EOK) {
        DLP_LOG_ERROR(LABEL, "Memcpy fail");
        FreePermissionPolicyMem();
        return;
    }
}

bool CheckAccountType(DlpAccountType accountType)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}d", accountType);
    if (accountType > APPLICATION_ACCOUNT || accountType < CLOUD_ACCOUNT) {
        DLP_LOG_ERROR(LABEL, "account type is invalid");
        return false;
    }
    return true;
}

void FreeCharBuffer(char* buff, uint32_t buffLen)
{
    if (buff != nullptr) {
        memset_s(buff, buffLen, 0, buffLen);
        delete[] buff;
        buff = nullptr;
    }
}

bool CheckAesParamLen(uint32_t len)
{
    DLP_LOG_DEBUG(LABEL, "Called, %{private}u", len);
    return VALID_AESPARAM_LEN.count(len) > 0;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS