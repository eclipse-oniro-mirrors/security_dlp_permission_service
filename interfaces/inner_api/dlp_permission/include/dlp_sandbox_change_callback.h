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

#ifndef DLP_SANDBOX_CHANGE_CALLBACK_H
#define DLP_SANDBOX_CHANGE_CALLBACK_H

#include "dlp_sandbox_change_callback_customize.h"
#include "dlp_sandbox_change_callback_stub.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpSandboxChangeCallback : public DlpSandboxChangeCallbackStub {
public:
    explicit DlpSandboxChangeCallback(const std::shared_ptr<DlpSandboxChangeCallbackCustomize> &customizedCallback);
    ~DlpSandboxChangeCallback() override;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo &result) override;

    void Stop();

private:
    std::shared_ptr<DlpSandboxChangeCallbackCustomize> customizedCallback_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_SANDBOX_CHANGE_CALLBACK_H