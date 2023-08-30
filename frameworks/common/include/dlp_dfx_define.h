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

#ifndef FRAMEWORKS_DFX_DLP_DFX_DEFINE_H
#define FRAMEWORKS_DFX_DLP_DFX_DEFINE_H

#include "hisysevent.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
typedef enum DlpEventCode {
    DLP_PERMISSION_VERIFY_ERROR = 101,
    DLP_FILE_CREATE_ERORR = 102,
    DLP_FILE_PARSE_ERROR = 103,
    DLP_INSTALL_SANDBOX_ERROR = 104,
    DLP_START_SANDBOX_ERROR = 105,

    DLP_FILE_CREATE_SUCCESS = 201,
    DLP_INSTALL_SANDBOX_SUCCESS = 202,
    DLP_START_SANDBOX_SUCCESS = 203,
} DlpEventCode;
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  FRAMEWORKS_DFX_DLP_DFX_DEFINE_H */
