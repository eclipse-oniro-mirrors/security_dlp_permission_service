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

#ifndef INTERFACES_INNER_API_DLP_PERMISSION_KIT_H
#define INTERFACES_INNER_API_DLP_PERMISSION_KIT_H

#include <string>
#include <vector>
#include "dlp_policy.h"
#include "dlp_permission_callback.h"
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class ClientGenerateDlpCertificateCallback : public GenerateDlpCertificateCallback {
public:
    ClientGenerateDlpCertificateCallback() = default;
    virtual ~ClientGenerateDlpCertificateCallback() = default;

    void onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override;

    int32_t result_ = -1;
    std::vector<uint8_t> cert_;
    bool isCallBack_ = false;
};

class ClientParseDlpCertificateCallback : public ParseDlpCertificateCallback {
public:
    ClientParseDlpCertificateCallback() = default;
    virtual ~ClientParseDlpCertificateCallback() = default;

    void onParseDlpCertificate(int32_t result, const PermissionPolicy& policy) override;

    int32_t result_ = -1;
    PermissionPolicy policy_;
    bool isCallBack_ = false;
};

class DlpPermissionKit {
public:
    static int32_t GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert);
    static int32_t ParseDlpCertificate(const std::vector<uint8_t>& cert, PermissionPolicy& policy);
    static int32_t InstallDlpSandbox(
        const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex);
    static int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId);
    static int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType);
    static int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId);
    static int32_t QueryDlpFileAccess(AuthPermType& permType);
    static int32_t IsInDlpSandbox(bool& inSandbox);
    static int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // INTERFACES_INNER_API_DLP_PERMISSION_KIT_H
