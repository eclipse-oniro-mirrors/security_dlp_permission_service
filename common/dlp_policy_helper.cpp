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

#include "dlp_policy_helper.h"
#include <chrono>
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
}  // namespace

static bool CheckAuthUserInfo(const AuthUserInfo& info)
{
    if (info.authAccount.size() > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Account size is invalid");
        return false;
    }

    if (info.authPerm <= 0 || info.authPerm >= PERM_MAX) {
        DLP_LOG_ERROR(LABEL, "Perm is invalid");
        return false;
    }
    uint64_t curTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (info.permExpiryTime < curTime) {
        DLP_LOG_ERROR(LABEL, "Perm expiry time is invalid");
        return false;
    };
    return true;
}

static bool CheckAuthUserInfoList(const std::vector<AuthUserInfo>& authUsers)
{
    if (authUsers.size() <= MAX_ACCOUNT_NUM) {
        for (auto iter : authUsers) {
            if (!CheckAuthUserInfo(iter)) {
                return false;
            }
        }
        return true;
    }
    DLP_LOG_ERROR(LABEL, "Auth users size is invalid");
    return false;
}

static bool CheckAeskey(const uint8_t* aeskey, uint32_t aeskeyLen)
{
    if (aeskey == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aeskey is null");
        return false;
    }
    if (aeskeyLen <= 0 || aeskeyLen > MAX_KEY_BYTES) {
        DLP_LOG_ERROR(LABEL, "Aeskey len is invalid, %{public}d", aeskeyLen);
        return false;
    }
    return true;
}

static bool CheckIv(const uint8_t* iv, uint32_t ivLen)
{
    if (iv == nullptr) {
        DLP_LOG_ERROR(LABEL, "Iv is invalid");
        return false;
    }
    if (ivLen <= 0 || ivLen > MAX_IV_BYTES) {
        DLP_LOG_ERROR(LABEL, "Iv len is invalid, %{public}d", ivLen);
        return false;
    }
    return true;
}

static bool CheckOwnerAccount(const std::string& ownerAccount)
{
    if (ownerAccount.empty() || ownerAccount.size() > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Owner account is invalid");
        return false;
    }
    return true;
}

bool CheckPermissionPolicy(const PermissionPolicy& policy)
{
    if (!CheckAeskey(policy.aeskey, policy.aeskeyLen) || !CheckIv(policy.iv, policy.ivLen) ||
        !CheckOwnerAccount(policy.ownerAccount) || !CheckAuthUserInfoList(policy.authUsers)) {
        return false;
    }
    return true;
}

bool CheckAccountType(AccountType accountType)
{
    if (accountType > APPLICATION_ACCOUNT || accountType < CLOUND_ACCOUNT) {
        DLP_LOG_ERROR(LABEL, "AccountType is invalid");
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

void FreeUint8Buffer(uint8_t* buff, uint32_t buffLen)
{
    if (buff != nullptr) {
        memset_s(buff, buffLen, 0, buffLen);
        delete[] buff;
        buff = nullptr;
    }
}

void FreePermissionPolicyMem(PermissionPolicy& policy)
{
    FreeUint8Buffer(policy.aeskey, policy.aeskeyLen);
    FreeUint8Buffer(policy.iv, policy.ivLen);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS