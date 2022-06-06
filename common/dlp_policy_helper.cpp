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

bool CheckAesParamLen(uint32_t len)
{
    return VALID_AESPARAM_LEN.count(len);
}

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

static bool CheckAccount(const std::string& ownerAccount)
{
    if (ownerAccount.empty() || ownerAccount.size() > MAX_ACCOUNT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Account is invalid");
        return false;
    }
    return true;
}

static bool CheckPerm(uint32_t perm)
{
    if (perm <= 0 || perm >= PERM_MAX) {
        DLP_LOG_ERROR(LABEL, "Perm is invalid");
        return false;
    }
    return true;
}

static bool CheckTime(uint64_t time)
{
    uint64_t curTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (time < curTime) {
        DLP_LOG_ERROR(LABEL, "Perm expiry time is invalid");
        return false;
    }
    return true;
}

static bool CheckAuthUserInfo(const AuthUserInfo& info)
{
    return (CheckAccount(info.authAccount) && CheckPerm(info.authPerm) && CheckTime(info.permExpiryTime));
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

bool CheckPermissionPolicy(const PermissionPolicy& policy)
{
    return (CheckAccount(policy.ownerAccount) && CheckAesParam(policy.aeskey, policy.aeskeyLen) &&
            CheckAesParam(policy.iv, policy.ivLen) && CheckAuthUserInfoList(policy.authUsers));
}

bool CheckAccountType(AccountType accountType)
{
    if (accountType > APPLICATION_ACCOUNT || accountType < CLOUD_ACCOUNT) {
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