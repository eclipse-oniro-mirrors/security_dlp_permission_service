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

#include "account_adapt.h"
#include "dlp_permission_log.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountAdapt"};
}

int8_t GetLocalAccountName(char** account, uint32_t userId)
{
    if (account == nullptr) {
        return -1;
    }
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> accountInfo =
        OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(userId);
    if (accountInfo.first) {
        *account = strdup(accountInfo.second.name_.c_str());
        return 0;
    }
    return -1;
}

int8_t GetUserIdFromUid(int32_t uid, int32_t* userId)
{
    if (OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, *userId) != 0) {
        DLP_LOG_INFO(LABEL, "get userId from uid failed, uid: %{public}d", uid);
        return -1;
    }
    return 0;
}
