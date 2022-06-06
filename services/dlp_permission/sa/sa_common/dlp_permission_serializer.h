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

#ifndef DLP_PERMISSION_SERIALIZER_H
#define DLP_PERMISSION_SERIALIZER_H

#include <string>
#include <vector>
#include "dlp_permission_policy_def.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionSerializer {
public:
    static DlpPermissionSerializer& GetInstance();
    DlpPermissionSerializer() = default;
    virtual ~DlpPermissionSerializer() = default;

    nlohmann::json SerializeAuthUserInfo(const AuthUserInfo& userInfo);
    int32_t DeserializeAuthUserInfo(const nlohmann::json& userInfoJson, AuthUserInfo& info);

    nlohmann::json SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers);
    int32_t DeserializeAuthUserList(
        const std::vector<nlohmann::json>& authUsersJson, std::vector<AuthUserInfo>& userList);

    int32_t SerializeDlpPermission(const PermissionPolicy& policy, nlohmann::json& permInfoJson);
    int32_t DeserializeDlpPermission(const nlohmann::json& permJson, PermissionPolicy& info);

private:
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERIALIZER_H
