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

#ifndef I_DLP_PERMISSION_CALLBACK_H
#define I_DLP_PERMISSION_CALLBACK_H

#include <vector>
#include "dlp_permission_policy_def.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class IDlpPermissionCallback : public IRemoteBroker {
public:
    virtual void onGenerateDlpCertificate(const int32_t result, const std::vector<uint8_t>& cert) = 0;

    virtual void onParseDlpCertificate(const PermissionPolicy& result) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.IDlpPermissionCallback");

    enum class InterfaceCode {
        ON_GENERATE_DLP_CERTIFICATE = 0xff03,
        ON_PARSE_DLP_CERTIFICATE = 0xff04,
    };
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // I_DLP_PERMISSION_CALLBACK_H
