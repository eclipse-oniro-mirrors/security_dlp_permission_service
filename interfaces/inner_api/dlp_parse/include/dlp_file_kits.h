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

#ifndef INTERFACES_INNER_API_DLP_FILE_KITS_H
#define INTERFACES_INNER_API_DLP_FILE_KITS_H

#include <string>
#include "dlp_file_manager.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const std::string TAG_ACTION_VIEW = "ACTION_VIEW";
static const std::string TAG_ACTION_EDIT = "ACTION_EDIT";
static const std::string TAG_KEY_FD = "keyFd";
static const std::string TAG_FILE_NAME = "fileName";
static const std::string DLP_FILE_SUFFIX = ".dlp";
static const std::string TAG_DLP_TEST_PARAM = "ohos.dlp.params.fd";

class DlpFileKits {
public:
    static bool GetSandboxFlag(const AAFwk::Want &want);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_KITS_H */
