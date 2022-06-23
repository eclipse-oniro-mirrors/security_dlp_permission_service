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

#include "parsecert_fuzzer.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "dlp_permission_serializer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "securec.h"
#undef private

using namespace OHOS::Security::DlpPermission;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionFuzzer"};

static std::string Uint8ArrayToString(const uint8_t* buff, size_t size)
{
    std::string str = "";
    for (size_t i = 0; i < size; i++) {
        str += (33 + buff[i] % (126 - 33));  // Visible Character Range 33 - 126
    }
    return str;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto seed = std::time(nullptr);
    std::srand(seed);
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount_ = Uint8ArrayToString(data, size);
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    encPolicy.SetAeskey(data, size);
    encPolicy.SetIv(data, size);
    int userNum = rand() % (size + 1);
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = Uint8ArrayToString(data, size);
        perminfo.authPerm = AuthPermType(1 + rand() % 3);  // perm type 1 to 3
        perminfo.permExpiryTime = curTime + rand() % 200;  // time range 0 to 200
        perminfo.authAccountType = DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    nlohmann::json jsonObj;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeDlpPermission(encPolicy, jsonObj);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Serialize fail");
        return;
    }
    std::string str = jsonObj.dump();
    std::vector<uint8_t> cert(str.begin(), str.end());
    PermissionPolicy policy;
    DlpPermissionKit::ParseDlpCertificate(cert, policy);
}

bool ParseCertFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
