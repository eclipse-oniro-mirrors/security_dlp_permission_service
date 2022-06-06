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

#ifndef DLP_PERMISSION_POLICY_DEF_H
#define DLP_PERMISSION_POLICY_DEF_H

#include <string>
#include <vector>
#include <cstdint>
#include <time.h>
#include "dlp_credential_service_defines.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum AuthPermType : uint32_t {
    READ_ONLY = 1,
    FULL_CONTROL = 2,
    PERM_MAX,
};

typedef struct AuthUserInfo {
    std::string authAccount;
    AuthPermType authPerm;
    uint64_t permExpiryTime;
} AuthUserInfo;

typedef struct PermissionPolicy {
    std::string ownerAccount;
    std::vector<AuthUserInfo> authUsers;
    uint8_t* aeskey;
    uint32_t aeskeyLen;
    uint8_t* iv;
    uint32_t ivLen;
} PermissionPolicy;
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_POLICY_DEF_H
