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

#include "dlp_permission_kit_test.h"
#include <chrono>
#include <thread>
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_policy_helper.h"
#include "hex_string.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKitTest"};
const uint32_t THREADS_NUM = 1;
const uint32_t USER_NUM = 10;
const uint32_t AESKEY_LEN = 32;
const uint32_t IV_LEN = 32;
const uint32_t WAIT_END_TIME = 2;
const uint32_t ACCOUNT_LENGTH = 20;
}  // namespace

static void PrintUint8ArrayToHex(const uint8_t* arr, uint32_t len)
{
    uint32_t strLen = len * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* str = new (std::nothrow) char[strLen];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }
    if (ByteToHexString(arr, len, str, strLen) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        memset_s(str, strlen(str), 0, strlen(str));
        delete[] str;
        str = nullptr;
        return;
    }
    std::cout << str << std::endl;
    memset_s(str, strlen(str), 0, strlen(str));
    delete[] str;
    str = nullptr;
}

static void PrintPolicy(const PermissionPolicy policy)
{
    std::cout << "owner:" << policy.ownerAccount << std::endl;
    std::cout << "aeskey in hex: ";
    PrintUint8ArrayToHex(policy.aeskey, policy.aeskeyLen);
    std::cout << "aeskeyLen: " << policy.aeskeyLen << std::endl;
    std::cout << "iv: ";
    PrintUint8ArrayToHex(policy.iv, policy.ivLen);
    std::cout << "ivLen: " << policy.ivLen << std::endl;

    std::cout << "account num: " << policy.authUsers.size() << std::endl;
    for (auto user : policy.authUsers) {
        std::cout << "account: " << user.authAccount << std::endl;
        std::cout << "permission: " << user.authPerm << std::endl;
        std::cout << "time: " << user.permExpiryTime << std::endl;
    }
}

void TestGenerateDlpCertificateCallback::onGenerateDlpCertificate(
    const int32_t result, const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
    std::cout << std::string(cert.begin(), cert.end()) << std::endl;

    std::shared_ptr<TestParseDlpCertificateCallback> callback = std::make_shared<TestParseDlpCertificateCallback>();
    int ret = DlpPermissionKit::ParseDlpCertificate(cert, callback);
    ASSERT_EQ(0, ret);
}

void TestParseDlpCertificateCallback::onParseDlpCertificate(const PermissionPolicy& result)
{
    DLP_LOG_INFO(LABEL, "Callback");
    std::cout << "policy after" << std::endl;
    PrintPolicy(result);
}

void DlpPermissionKitTest::SetUpTestCase()
{
    // make test case clean
    DLP_LOG_INFO(LABEL, "SetUpTestCase.");
}

void DlpPermissionKitTest::TearDownTestCase()
{
    DLP_LOG_INFO(LABEL, "TearDownTestCase.");
}

void DlpPermissionKitTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "SetUp ok.");
}

void DlpPermissionKitTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown.");
}

uint8_t* GenerateRandArray(int len)
{
    uint8_t* str = new (std::nothrow) uint8_t[len];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }
    for (int i = 0; i < len; i++) {
        str[i] = rand() % 255;  // uint8_t range 0 ~ 255
    }
    return str;
}

std::string GenerateRandStr(int len)
{
    char* str = new (std::nothrow) char[len + 1];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return "";
    }
    for (int i = 0; i < len; i++) {
        str[i] = 33 + rand() % (126 - 33);  // Visible Character Range 33 - 126
    }
    str[len] = '\0';
    std::string res = str;
    delete[] str;
    return res;
}

static void FuzzTest()
{
    uint64_t curTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    srand(time(nullptr));
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount = GenerateRandStr(ACCOUNT_LENGTH);
    encPolicy.aeskey = GenerateRandArray(AESKEY_LEN);
    encPolicy.aeskeyLen = AESKEY_LEN;
    encPolicy.iv = GenerateRandArray(IV_LEN);
    encPolicy.ivLen = IV_LEN;
    int userNum = 0 + rand() % USER_NUM;
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(ACCOUNT_LENGTH),
            .authPerm = AuthPermType(1 + rand() % 2),         // perm type 1 to 2
            .permExpiryTime = curTime + 100 + rand() % 200};  // time range 100 to 300
        encPolicy.authUsers.emplace_back(perminfo);
    }
    std::cout << "policy before" << std::endl;
    PrintPolicy(encPolicy);
    std::shared_ptr<TestGenerateDlpCertificateCallback> callback =
        std::make_shared<TestGenerateDlpCertificateCallback>();
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, DOMAIN_ACCOUNT, callback);

    FreePermissionPolicyMem(encPolicy);
}

/**
 * @tc.name: GenerateDlpCertificate001
 * @tc.desc: GenerateDlpCertificate test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GenerateDlpCertificate001, TestSize.Level1)
{
    std::vector<std::thread> threads;
    for (size_t i = 0; i < THREADS_NUM; ++i) {
        threads.emplace_back(std::thread(FuzzTest));
    }

    for (auto& thread : threads) {
        thread.join();
    }
    sleep(WAIT_END_TIME);
}
