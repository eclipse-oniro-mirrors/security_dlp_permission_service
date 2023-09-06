/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "dlp_credential_client.h"
#include "dlp_policy.h"
#include "nlohmann/json.hpp"
#include "fifo_map.hpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
template<class K, class V, class dummy_compare, class A>
using fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
using unordered_json = nlohmann::basic_json<fifo_map>;
class DlpPermissionSerializer {
public:
    static DlpPermissionSerializer& GetInstance();
    DlpPermissionSerializer() = default;
    virtual ~DlpPermissionSerializer() = default;

    int32_t SerializeDlpPermission(const PermissionPolicy& policy, unordered_json& permInfoJson);
    int32_t DeserializeDlpPermission(const unordered_json& permJson, PermissionPolicy& policy);

    int32_t SerializeEncPolicyData(const DLP_EncPolicyData& encData, unordered_json& encDataJson);
    int32_t DeserializeEncPolicyData(
        const unordered_json& encDataJson, DLP_EncPolicyData& encData, bool isOff);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERIALIZER_H
