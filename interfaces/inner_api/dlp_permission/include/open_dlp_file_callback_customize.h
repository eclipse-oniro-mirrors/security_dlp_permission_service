/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OPEN_DLP_FILE_CALLBACK_CUSTOMIZE_H
#define OPEN_DLP_FILE_CALLBACK_CUSTOMIZE_H

#include <string>
#include "open_dlp_file_callback_info.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class OpenDlpFileCallbackCustomize {
public:
    OpenDlpFileCallbackCustomize();

    virtual ~OpenDlpFileCallbackCustomize();
    virtual void OnOpenDlpFile(OpenDlpFileCallbackInfo& result) = 0;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // OPEN_DLP_FILE_CALLBACK_CUSTOMIZE_H
