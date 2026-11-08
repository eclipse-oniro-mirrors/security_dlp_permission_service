/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_DLP_PERMISSION_NAPI_COMMON_NAPI_H
#define INTERFACES_KITS_DLP_PERMISSION_NAPI_COMMON_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "napi_common.h"
#include "napi_error_msg.h"
#include "parameters.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef);

// IS_CAR and IS_EMULATOR only one can be defined at a time.
inline bool CheckDevice(napi_env env)
{
#ifdef IS_CAR
    DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED);
    return true;
#endif
#ifdef IS_EMULATOR
    DlpNapiThrow(env, DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR);
    return true;
#endif
    return false;
}

// IS_CAR and IS_EMULATOR only one can be defined at a time.
inline int32_t CheckDevice()
{
#ifdef IS_CAR
    return DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED;
#endif
#ifdef IS_EMULATOR
    return DLP_DEVICE_ERROR_CAPABILITY_NOT_SUPPORTED_EMULATOR;
#endif
    return DLP_OK;
}

inline bool IsOversea()
{
    return OHOS::system::GetParameter("const.cust.is_oversea", "true") == "true";
}

inline bool CheckOverseaNotSupported(napi_env env)
{
    static constexpr OHOS::HiviewDFX::HiLogLabel OVERSEA_LABEL = {
        LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionNapi"
    };
    if (!IsOversea()) {
        DLP_LOG_INFO(OVERSEA_LABEL, "is not oversea, support DLP feature");
        return false;
    }
    std::string jsErrMsg = "Capability not supported. Possible causes: the car does not support DLP feature.";
    DLP_LOG_ERROR(OVERSEA_LABEL, "%{public}s", jsErrMsg.c_str());
    DlpNapiThrow(env, ERR_JS_CAPABILITY_NOT_SUPPORTED, jsErrMsg);
    return true;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif /*  INTERFACES_KITS_DLP_PERMISSION_NAPI_COMMON_NAPI_H */
