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

const uint32_t ACCOUNT_LENGTH = 20;
const uint32_t AESKEY_LEN = 32;
const uint32_t IV_LEN = 32;
const uint32_t USER_NUM = 10;
const int AUTH_PERM = 1;
const int64_t DELTA_EXPIRY_TIME = 200;
const uint32_t ACCOUNT_TYPE = DOMAIN_ACCOUNT;

const uint32_t INVALID_ACCOUNT_LENGTH_UPPER = 2048;
const uint32_t INVALID_ACCOUNT_LENGTH_LOWER = 0;
const uint32_t INVALID_AESKEY_LEN_UPPER = 256;
const uint32_t INVALID_AESKEY_LEN_LOWER = 0;
const uint32_t INVALID_IV_LEN_UPPER = 256;
const uint32_t INVALID_IV_LEN_LOWER = 0;
const uint32_t INVALID_USER_NUM_UPPER = 200;
const uint32_t INVALID_USER_NUM_LOWER = 0;
const uint32_t INVALID_AUTH_PERM_UPPER = 5;
const uint32_t INVALID_AUTH_PERM_LOWER = 0;
const int64_t INVALID_DELTA_EXPIRY_TIME = -100;
const uint32_t INVALID_ACCOUNT_TYPE_UPPER = 4;
const uint32_t INVALID_ACCOUNT_TYPE_LOWER = 0;
}  // namespace

void TestGenerateDlpCertificateCallback::onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
    (void)result;
    std::shared_ptr<TestParseDlpCertificateCallback> callback = std::make_shared<TestParseDlpCertificateCallback>();
    DlpPermissionKit::ParseDlpCertificate(cert, callback);
}

void TestParseDlpCertificateCallback::onParseDlpCertificate(int32_t result, const PermissionPolicy& policy)
{
    DLP_LOG_INFO(LABEL, "Callback");
    (void)result;
    (void)policy;
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

static uint8_t* GenerateRandArray(uint32_t len)
{
    uint8_t* str = new (std::nothrow) uint8_t[len];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }
    for (uint32_t i = 0; i < len; i++) {
        str[i] = rand() % 255;  // uint8_t range 0 ~ 255
    }
    return str;
}

static std::string GenerateRandStr(uint32_t len)
{
    char* str = new (std::nothrow) char[len + 1];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return "";
    }
    for (uint32_t i = 0; i < len; i++) {
        str[i] = 33 + rand() % (126 - 33);  // Visible Character Range 33 - 126
    }
    str[len] = '\0';
    std::string res = str;
    delete[] str;
    return res;
}

static void GeneratePolicy(PermissionPolicy& encPolicy, uint32_t ownerAccountLen, uint32_t aeskeyLen, uint32_t ivLen,
    uint32_t userNum, uint32_t authAccountLen, uint32_t authPerm, int64_t deltaTime)
{
    uint64_t curTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto seed = std::time(nullptr);
    std::srand(seed);
    encPolicy.ownerAccount = GenerateRandStr(ownerAccountLen);
    encPolicy.aeskey = GenerateRandArray(aeskeyLen);
    encPolicy.aeskeyLen = aeskeyLen;
    encPolicy.iv = GenerateRandArray(ivLen);
    encPolicy.ivLen = ivLen;
    for (uint32_t user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(authAccountLen),
            .authPerm = (AuthPermType)authPerm,
            .permExpiryTime = curTime + deltaTime};
        encPolicy.authUsers.emplace_back(perminfo);
    }
}

static void FuzzTest()
{
    uint64_t curTime =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto seed = std::time(nullptr);
    std::srand(seed);
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount = GenerateRandStr(ACCOUNT_LENGTH);
    encPolicy.aeskey = GenerateRandArray(AESKEY_LEN);
    encPolicy.aeskeyLen = AESKEY_LEN;
    encPolicy.iv = GenerateRandArray(IV_LEN);
    encPolicy.ivLen = IV_LEN;
    int userNum = rand() % USER_NUM;
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(ACCOUNT_LENGTH),
            .authPerm = AuthPermType(1 + rand() % 2),         // perm type 1 to 2
            .permExpiryTime = curTime + 100 + rand() % 200};  // time range 100 to 300
        encPolicy.authUsers.emplace_back(perminfo);
    }
    std::shared_ptr<TestGenerateDlpCertificateCallback> callback =
        std::make_shared<TestGenerateDlpCertificateCallback>();
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, (AccountType)ACCOUNT_TYPE, callback);
    FreePermissionPolicyMem(encPolicy);
}

static int32_t TestGenerateDlpCertWithInvalidParam(uint32_t ownerAccountLen, uint32_t aeskeyLen, uint32_t ivLen,
    uint32_t userNum, uint32_t authAccountLen, uint32_t authPerm, int64_t deltaTime, uint32_t accountType)
{
    PermissionPolicy encPolicy;
    GeneratePolicy(encPolicy, ownerAccountLen, aeskeyLen, ivLen, userNum, authAccountLen, authPerm, deltaTime);
    std::shared_ptr<TestGenerateDlpCertificateCallback> callback =
        std::make_shared<TestGenerateDlpCertificateCallback>();
    int32_t res = DlpPermissionKit::GenerateDlpCertificate(encPolicy, (AccountType)accountType, callback);
    FreePermissionPolicyMem(encPolicy);
    return res;
}

/**
 * @tc.name: GenerateDlpCertificate001
 * @tc.desc: GenerateDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GenerateDlpCertificate001, TestSize.Level1)
{
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(INVALID_ACCOUNT_LENGTH_UPPER, AESKEY_LEN, IV_LEN,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(INVALID_ACCOUNT_LENGTH_LOWER, AESKEY_LEN, IV_LEN,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, INVALID_AESKEY_LEN_UPPER, IV_LEN,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, INVALID_AESKEY_LEN_LOWER, IV_LEN,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_UPPER,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_LOWER,
                                     USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(
        DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                               INVALID_USER_NUM_UPPER, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_OK, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, INVALID_USER_NUM_LOWER,
                          ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     INVALID_ACCOUNT_LENGTH_UPPER, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     INVALID_ACCOUNT_LENGTH_LOWER, AUTH_PERM, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     ACCOUNT_LENGTH, INVALID_AUTH_PERM_UPPER, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     ACCOUNT_LENGTH, INVALID_AUTH_PERM_LOWER, DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     ACCOUNT_LENGTH, AUTH_PERM, INVALID_DELTA_EXPIRY_TIME, ACCOUNT_TYPE));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, INVALID_ACCOUNT_TYPE_UPPER));
    ASSERT_EQ(DLP_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM,
                                     ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME, INVALID_ACCOUNT_TYPE_LOWER));
    PermissionPolicy encPolicy;
    GeneratePolicy(
        encPolicy, ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME);
    int32_t res = DlpPermissionKit::GenerateDlpCertificate(encPolicy, (AccountType)ACCOUNT_TYPE, nullptr);
    FreePermissionPolicyMem(encPolicy);
    ASSERT_EQ(DLP_VALUE_INVALID, res);
}

/**
 * @tc.name: GenerateDlpCertificate002
 * @tc.desc: GenerateDlpCertificate test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GenerateDlpCertificate002, TestSize.Level1)
{
    uint32_t threadsNum = 100;
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < threadsNum; ++i) {
        threads.emplace_back(std::thread(FuzzTest));
    }

    for (auto& thread : threads) {
        thread.join();
    }
    uint32_t waitEndTime = 1;
    sleep(waitEndTime);
}

/**
 * @tc.name: ParseDlpCertificate001
 * @tc.desc: ParseDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, ParseDlpCertificate001, TestSize.Level1)
{
    std::vector<uint8_t> cert;
    std::shared_ptr<TestParseDlpCertificateCallback> callback = std::make_shared<TestParseDlpCertificateCallback>();
    ASSERT_EQ(DLP_VALUE_INVALID, DlpPermissionKit::ParseDlpCertificate(cert, callback));
    cert = {1, 2, 3};
    ASSERT_EQ(DLP_VALUE_INVALID, DlpPermissionKit::ParseDlpCertificate(cert, nullptr));
}
