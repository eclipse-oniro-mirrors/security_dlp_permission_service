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

#ifndef DLP_PERMISSION_DEF_H
#define DLP_PERMISSION_DEF_H

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum DLPErrCode : int32_t {
    DLP_TASK_DUPLICATE = -8,
    DLP_PERMISSION_BUSY = -7,
    DLP_CREDENTIAL_FAIL = -6,
    DLP_REQUEST_FAIL = -5,
    DLP_OPERATE_JSON_FAIL = -4,
    DLP_OPERATE_MEMORY_FAIL = -3,
    DLP_OPERATE_PARCEL_FAIL = -2,
    DLP_VALUE_INVALID = -1,
    DLP_OK = 0,
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_DEF_H
