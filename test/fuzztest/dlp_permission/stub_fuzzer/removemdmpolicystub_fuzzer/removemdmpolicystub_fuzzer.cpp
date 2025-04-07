/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "removemdmpolicystub_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"
#include "securec.h"
#include "token_setproc.h"

constexpr uint8_t STATUS_NUM = 2;

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const int32_t EDM_UID = 3057;
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

static void FuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_REMOVE_M_D_M_POLICY);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);

    MessageParcel datas1;
    datas1.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    MessageParcel reply1;
    MessageOption option1;
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service1->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service1->OnRemoteRequest(code, datas1, reply1, option1);
}

bool GetMDMPolicyFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    setuid(OHOS::EDM_UID);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetMDMPolicyFuzzTest(data, size);
    return 0;
}
