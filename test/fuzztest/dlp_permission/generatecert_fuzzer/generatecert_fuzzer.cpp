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

#include "generatecert_fuzzer.h"
#include "dlp_permission_log.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "securec.h"
#undef private

using namespace OHOS::Security::DlpPermission;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionFuzzer"};

void TestGenerateDlpCertificateCallback::onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
}

static std::string Uint8ArrayToString(const uint8_t* buff, size_t size)
{
    std::string str = "";
    for (size_t i = 0; i < size; i++) {
        str += (33 + buff[i] % (126 - 33));  // Visible Character Range 33 - 126
    }
    return str;
}

static void FuzzTest(uint8_t* buff, size_t size)
{
    auto seed = std::time(nullptr);
    std::srand(seed);
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount = Uint8ArrayToString(buff, size);
    encPolicy.aeskey = buff;
    encPolicy.aeskeyLen = size;
    encPolicy.iv = buff;
    encPolicy.ivLen = size;
    int userNum = rand() % (size + 1);
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = Uint8ArrayToString(buff, size);
        perminfo.authPerm = AuthPermType(1 + rand() % 3);  // perm type 1 to 3
        perminfo.permExpiryTime = curTime + rand() % 200;  // time range 0 to 200
        encPolicy.authUsers.emplace_back(perminfo);
    }
    std::shared_ptr<TestGenerateDlpCertificateCallback> callback =
        std::make_shared<TestGenerateDlpCertificateCallback>();
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, DOMAIN_ACCOUNT, callback);
}

bool GenerateCertFuzzTest(const uint8_t* data, size_t size)
{
    uint8_t* buff = nullptr;
    if (size > 0 && data != nullptr) {
        buff = new (std::nothrow) uint8_t[size];
        if (buff == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return false;
        }
        if (memcpy_s(buff, size, data, size) != EOK) {
            DLP_LOG_ERROR(LABEL, "Memcpy_s fail");
            delete[] buff;
            return false;
        }
    } else {
        buff = nullptr;
    }
    FuzzTest(buff, size);
    if (buff) {
        memset_s(buff, size, 0, size);
        delete[] buff;
        buff = nullptr;
    }
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
