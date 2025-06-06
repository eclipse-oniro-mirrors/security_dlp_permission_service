/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "account_adapt.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "domain_account_client.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountAdapt"};
constexpr static int UID_TRANSFORM_DIVISOR = 200000;
}
using OHOS::Security::DlpPermission::DLP_PARSE_ERROR_ACCOUNT_INVALID;
using OHOS::Security::DlpPermission::DLP_OK;
using OHOS::AccountSA::OhosAccountInfo;
using OHOS::AccountSA::OhosAccountKits;
using OHOS::AccountSA::ACCOUNT_STATE_UNBOUND;
using OHOS::AccountSA::DomainAccountClient;
using OHOS::AccountSA::DomainAccountStatus;
using OHOS::AccountSA::DomainAccountInfo;

int32_t GetCallingUserId(void)
{
    int32_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    return (callingUid / UID_TRANSFORM_DIVISOR);
}

int8_t GetLocalAccountName(char** account, uint32_t userId)
{
    if (account == nullptr) {
        return -1;
    }
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> accountInfo =
        OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(userId);
    if (accountInfo.first) {
        *account = strdup(accountInfo.second.name_.c_str());
        return 0;
    }
    return -1;
}

bool GetUserIdByForegroundAccount(int32_t* userId)
{
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(*userId);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "GetForegroundOsAccountLocalId failed %{public}d", res);
        return false;
    }
    return true;
}

int32_t GetLocalAccountUid(std::string& accountUid)
{
    OHOS::AccountSA::OhosAccountInfo accountInfo;
    int32_t ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(GetCallingUserId(),
        accountInfo);
    if (ret != 0) {
        return ret;
    }
    accountUid = accountInfo.GetRawUid();
    return 0;
}

int8_t GetUserIdFromUid(int32_t uid, int32_t* userId)
{
    if (OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, *userId) != 0) {
        DLP_LOG_INFO(LABEL, "get userId from uid failed, uid: %{public}d", uid);
        return -1;
    }
    return 0;
}

bool IsAccountLogIn(uint32_t osAccountId, AccountType accountType, const DlpBlob* accountId)
{
    if (accountId == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid input params.");
        return false;
    }

    int32_t res;
    if (accountType == CLOUD_ACCOUNT) {
        OhosAccountInfo accountInfo;
        res = OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(osAccountId, accountInfo);
        if (res != DLP_SUCCESS) {
            DLP_LOG_ERROR(LABEL, "GetOsAccountDistributedInfo from OhosAccountKits failed, res:%{public}d.", res);
            return false;
        }
        if (accountInfo.status_ == ACCOUNT_STATE_UNBOUND) {
            DLP_LOG_ERROR(LABEL, "GetOsAccountDistributedInfo from OhosAccountKits is not login.");
            return false;
        }
        return true;
    }

    if (accountType != DOMAIN_ACCOUNT) {
        // app account status default value is true
        return true;
    }

    DomainAccountInfo info;
    std::string account(reinterpret_cast<char*>(accountId->data), accountId->size);
    info.accountId_ = account;
    DLP_LOG_INFO(LABEL, "Get accountType:%{public}d", accountType);
    DomainAccountStatus status;
    res = DomainAccountClient::GetInstance().GetAccountStatus(info, status);
    if (res != OHOS::ERR_OK) {
        DLP_LOG_ERROR(LABEL, "GetAccountStatus from OsAccountKits failed, res:%{public}d.", res);
        return false;
    }
    if (status != DomainAccountStatus::LOGIN) {
        DLP_LOG_ERROR(LABEL, "Domain account status is not login. status=%{public}d.", status);
        return false;
    }
    return true;
}

int32_t GetDomainAccountName(char** account)
{
    int32_t userId;
    if (!GetUserIdByForegroundAccount(&userId)) {
        DLP_LOG_ERROR(LABEL, "GetUserIdByForegroundAccount error");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    OHOS::AccountSA::OsAccountInfo osAccountInfo;
    if (OHOS::AccountSA::OsAccountManager::QueryOsAccountById(userId, osAccountInfo) != 0) {
        DLP_LOG_ERROR(LABEL, "GetOsAccountLocalIdFromDomain return not 0");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        DLP_LOG_ERROR(LABEL, "accountName_ empty");
        return DLP_PARSE_ERROR_ACCOUNT_INVALID;
    }
    *account = strdup(domainInfo.accountName_.c_str());
    return DLP_OK;
}