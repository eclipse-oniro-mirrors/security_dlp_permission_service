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

#ifndef I_DLP_PERMISSION_SERVICE_H
#define I_DLP_PERMISSION_SERVICE_H

#include <string>
#include "dlp_policy_parcel.h"
#include "i_dlp_permission_callback.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

class IDlpPermissionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.IDlpPermissionService");

    virtual int GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, AccountType accountType, sptr<IDlpPermissionCallback>& callback) = 0;

    virtual int ParseDlpCertificate(const std::vector<uint8_t>& cert, sptr<IDlpPermissionCallback>& callback) = 0;

    enum class InterfaceCode {
        GENERATE_DLP_CERTIFICATE = 0xff01,
        PARSE_DLP_CERTIFICATE = 0xff02,
    };
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // I_DLP_PERMISSION_SERVICE_H
