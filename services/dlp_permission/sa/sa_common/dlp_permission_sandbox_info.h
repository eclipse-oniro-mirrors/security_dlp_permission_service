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

#ifndef DLP_PERMISSION_SANDBOX_INFO_H
#define DLP_PERMISSION_SANDBOX_INFO_H

#include "dlp_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpSandboxInfo {
public:
    int uid = -1;
    int32_t userId = -1;
    int32_t appIndex = -1;
    unsigned int tokenId = 0;
    AuthPermType permType = DEFAULT_PERM;
    std::string bundleName;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SANDBOX_INFO_H