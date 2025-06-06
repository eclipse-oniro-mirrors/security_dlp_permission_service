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

#ifndef INTERFACES_INNER_API_DLP_PERMISSION_INCLUDE_DLP_PERMISSION_KIT_H
#define INTERFACES_INNER_API_DLP_PERMISSION_INCLUDE_DLP_PERMISSION_KIT_H

#include <string>
#include <vector>
#include "cert_parcel.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionKit {
public:
    static int32_t GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert);
    static int32_t ParseDlpCertificate(sptr<CertParcel>& certParcel, PermissionPolicy& policy,
        const std::string& appId, bool offlineAccess);
    static int32_t SetReadFlag(uint32_t uid);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // INTERFACES_INNER_API_DLP_PERMISSION_INCLUDE_DLP_PERMISSION_KIT_H
