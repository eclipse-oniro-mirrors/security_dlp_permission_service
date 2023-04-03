/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "want.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

class IDlpPermissionService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.IDlpPermissionService");

    virtual int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) = 0;

    virtual int32_t ParseDlpCertificate(const std::vector<uint8_t>& cert, uint32_t flag,
        sptr<IDlpPermissionCallback>& callback) = 0;

    virtual int32_t InstallDlpSandbox(
        const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex) = 0;

    virtual int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) = 0;
    virtual int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType) = 0;

    virtual int32_t QueryDlpFileAccess(AuthPermType& permType) = 0;

    virtual int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId) = 0;

    virtual int32_t IsInDlpSandbox(bool& inSandbox) = 0;

    virtual int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType) = 0;

    virtual int32_t RegisterDlpSandboxChangeCallback(const sptr<IRemoteObject> &callback) = 0;

    virtual int32_t UnRegisterDlpSandboxChangeCallback(bool &result) = 0;

    enum class InterfaceCode {
        GENERATE_DLP_CERTIFICATE = 0xff01,
        PARSE_DLP_CERTIFICATE = 0xff02,
        INSTALL_DLP_SANDBOX = 0xff03,
        UNINSTALL_DLP_SANDBOX = 0xff04,
        GET_SANDBOX_EXTERNAL_AUTH = 0xff05,
        QUERY_DLP_FILE_ACCESS = 0xff06,
        IS_IN_DLP_SANDBOX = 0xff07,
        GET_DLP_SUPPORT_FILE_TYPE = 0xff08,
        QUERY_DLP_FILE_ACCESS_BY_TOKEN_ID = 0xff09,
        REGISTER_DLP_SANDBOX_CHANGE_CALLBACK = 0xff0a,
        UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK = 0xff0b,
    };
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif  // I_DLP_PERMISSION_SERVICE_H
