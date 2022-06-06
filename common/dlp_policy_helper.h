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

#ifndef DLP_POLICY_HELPER_H
#define DLP_POLICY_HELPER_H

#include "dlp_permission_policy_def.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
bool CheckPermissionPolicy(const PermissionPolicy& policy);
bool CheckAccountType(AccountType accountType);
bool CheckAesParamLen(uint32_t len);
void FreeCharBuffer(char* buff, uint32_t buffLen);
void FreeUint8Buffer(uint8_t* buff, uint32_t buffLen);
void FreePermissionPolicyMem(PermissionPolicy& policy);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_POLICY_HELPER_H
