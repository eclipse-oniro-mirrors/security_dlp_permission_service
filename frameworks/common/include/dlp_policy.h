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

#ifndef FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H
#define FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H

#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum DlpAccountType : uint32_t {
    INVALID_ACCOUNT = 0,
    CLOUD_ACCOUNT = 1,
    DOMAIN_ACCOUNT = 2,
    APPLICATION_ACCOUNT = 3,
};

enum AuthPermType : uint32_t {
    READ_ONLY = 1,
    FULL_CONTROL = 2,
    PERM_MAX,
};

typedef struct AuthUserInfo {
    std::string authAccount;
    AuthPermType authPerm = PERM_MAX;
    uint64_t permExpiryTime = 0;
    DlpAccountType authAccountType = INVALID_ACCOUNT;
} AuthUserInfo;

struct DlpProperty {
    std::string ownerAccount;
    std::vector<AuthUserInfo> authUsers;
    std::string contractAccount;
    DlpAccountType ownerAccountType = INVALID_ACCOUNT;
};

class PermissionPolicy final {
public:
    PermissionPolicy();
    PermissionPolicy(const DlpProperty& property);
    ~PermissionPolicy();
    void CopyPermissionPolicy(const PermissionPolicy& srcPolicy);
    void FreePermissionPolicyMem();

    bool IsValid() const;
    void SetAeskey(const uint8_t* key, uint32_t keyLen);
    uint8_t* GetAeskey() const;
    uint32_t GetAeskeyLen() const;
    void SetIv(const uint8_t* iv, uint32_t ivLen);
    uint8_t* GetIv() const;
    uint32_t GetIvLen() const;

    std::string ownerAccount_;
    DlpAccountType ownerAccountType_;
    std::vector<AuthUserInfo> authUsers_;

private:
    uint8_t* aeskey_;
    uint32_t aeskeyLen_;
    uint8_t* iv_;
    uint32_t ivLen_;
};

void FreeCharBuffer(char* buff, uint32_t buffLen);
bool CheckAccountType(DlpAccountType accountType);
bool CheckAesParamLen(uint32_t len);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H
