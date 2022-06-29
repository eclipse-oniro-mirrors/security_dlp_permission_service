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

#include "dlp_file_kits.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
bool DlpFileKits::GetSandboxFlag(const OHOS::AAFwk::Want &want)
{
    if (want.HasParameter(TAG_DLP_TEST_PARAM) && want.GetIntParam(TAG_DLP_TEST_PARAM, 0) != 0) {
        return true;
    }
    return false;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
