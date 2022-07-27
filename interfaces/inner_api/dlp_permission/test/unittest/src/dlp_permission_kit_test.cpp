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
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_policy.h"
#include "hex_string.h"
#include "securec.h"
#include "token_setproc.h"
#include "want.h"
#include "bundle_mgr_client.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKitTest"};

const uint32_t ACCOUNT_LENGTH = 20;
const uint32_t AESKEY_LEN = 32;
const uint32_t IV_LEN = 32;
const uint32_t USER_NUM = 10;
const int AUTH_PERM = 1;
const int64_t DELTA_EXPIRY_TIME = 200;

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

const int32_t DEFAULT_USERID = 100;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_dlpManagerTokenId = 0;
static int32_t g_selfUid = 0;
}  // namespace

static void SaveTokenId()
{
    g_selfTokenId = GetSelfTokenID();
    DLP_LOG_INFO(LABEL, "get self tokenId is %{public}d", g_selfTokenId);
    g_dlpManagerTokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, DLP_MANAGER_APP, 0);
    DLP_LOG_INFO(LABEL, "get dlp manager tokenId is %{public}d", g_dlpManagerTokenId);
    g_selfUid = getuid();
    DLP_LOG_INFO(LABEL, "get self uid is %{public}d", g_selfUid);
}

static void SetTokenIdToManagerApp()
{
    DLP_LOG_INFO(LABEL, "set self tokenId from %{public}lu to %{public}d", GetSelfTokenID(), g_dlpManagerTokenId);
    if (SetSelfTokenID(g_dlpManagerTokenId) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set self tokenId fail");
    }
}

static void RecoverTokenId()
{
    DLP_LOG_INFO(LABEL, "recover self tokenId from %{public}lu to %{public}d", GetSelfTokenID(), g_selfTokenId);
    if (SetSelfTokenID(g_selfTokenId) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "recover self tokenId fail");
    }
}

static AccessTokenID GetTokenId(int userID, const std::string& bundleName, int instIndex)
{
    RecoverTokenId();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    DLP_LOG_INFO(LABEL, "get app tokenId is %{public}d", tokenId);
    SetTokenIdToManagerApp();
    return tokenId;
}

static int32_t GetAppUid(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    RecoverTokenId();
    OHOS::AppExecFwk::BundleInfo info;
    OHOS::AppExecFwk::BundleMgrClient bundleMgrClient;
    if (appIndex > 0) {
        if (bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "get sandbox app info fail");
        }
    } else {
        if (!bundleMgrClient.GetBundleInfo(bundleName, OHOS::AppExecFwk::GET_BUNDLE_DEFAULT, info, userId)) {
            DLP_LOG_ERROR(LABEL, "get app info fail");
        }
    }
    DLP_LOG_INFO(LABEL, "get app uid: %{public}d", info.uid);
    SetTokenIdToManagerApp();
    return info.uid;
}

void DlpPermissionKitTest::SetUpTestCase()
{
    // make test case clean
    DLP_LOG_INFO(LABEL, "SetUpTestCase.");
    SaveTokenId();
    SetTokenIdToManagerApp();
}

void DlpPermissionKitTest::TearDownTestCase()
{
    DLP_LOG_INFO(LABEL, "TearDownTestCase.");
    RecoverTokenId();
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
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto seed = std::time(nullptr);
    std::srand(seed);
    encPolicy.ownerAccount_ = GenerateRandStr(ownerAccountLen);
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    uint8_t* key = GenerateRandArray(aeskeyLen);
    encPolicy.SetAeskey(key, aeskeyLen);
    if (key != nullptr) {
        delete[] key;
        key = nullptr;
    }
    uint8_t* iv = GenerateRandArray(ivLen);
    encPolicy.SetIv(iv, ivLen);
    if (iv != nullptr) {
        delete[] iv;
        iv = nullptr;
    }
    for (uint32_t user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(authAccountLen),
            .authPerm = static_cast<AuthPermType>(authPerm),
            .permExpiryTime = curTime + deltaTime,
            .authAccountType = DOMAIN_ACCOUNT};
        encPolicy.authUsers_.emplace_back(perminfo);
    }
}

static void FuzzTest()
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto seed = std::time(nullptr);
    std::srand(seed);
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount_ = GenerateRandStr(ACCOUNT_LENGTH);
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    uint8_t* key = GenerateRandArray(AESKEY_LEN);
    encPolicy.SetAeskey(key, AESKEY_LEN);
    if (key != nullptr) {
        delete[] key;
        key = nullptr;
    }
    uint8_t* iv = GenerateRandArray(IV_LEN);
    encPolicy.SetIv(iv, IV_LEN);
    if (iv != nullptr) {
        delete[] iv;
        iv = nullptr;
    }
    int userNum = rand() % USER_NUM;
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(ACCOUNT_LENGTH),
            .authPerm = AuthPermType(1 + rand() % 2),        // perm type 1 to 2
            .permExpiryTime = curTime + 100 + rand() % 200,  // time range 100 to 300
            .authAccountType = DOMAIN_ACCOUNT};
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    std::vector<uint8_t> cert;
    DlpPermissionKit::GenerateDlpCertificate(encPolicy, cert);
    PermissionPolicy policy;
    DlpPermissionKit::ParseDlpCertificate(cert, policy);
}

static int32_t TestGenerateDlpCertWithInvalidParam(uint32_t ownerAccountLen, uint32_t aeskeyLen, uint32_t ivLen,
    uint32_t userNum, uint32_t authAccountLen, uint32_t authPerm, int64_t deltaTime)
{
    PermissionPolicy encPolicy;
    GeneratePolicy(encPolicy, ownerAccountLen, aeskeyLen, ivLen, userNum, authAccountLen, authPerm, deltaTime);
    std::vector<uint8_t> cert;
    int32_t res = DlpPermissionKit::GenerateDlpCertificate(encPolicy, cert);
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
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(INVALID_ACCOUNT_LENGTH_UPPER, AESKEY_LEN,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(INVALID_ACCOUNT_LENGTH_LOWER, AESKEY_LEN,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, INVALID_AESKEY_LEN_UPPER,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, INVALID_AESKEY_LEN_LOWER,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        TestGenerateDlpCertWithInvalidParam(
            ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_UPPER, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        TestGenerateDlpCertWithInvalidParam(
            ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_LOWER, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             INVALID_USER_NUM_UPPER, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(DLP_OK, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN, INVALID_USER_NUM_LOWER,
                          ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, INVALID_ACCOUNT_LENGTH_UPPER, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, INVALID_ACCOUNT_LENGTH_LOWER, AUTH_PERM, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, ACCOUNT_LENGTH, INVALID_AUTH_PERM_UPPER, DELTA_EXPIRY_TIME));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, ACCOUNT_LENGTH, INVALID_AUTH_PERM_LOWER, DELTA_EXPIRY_TIME));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                                   USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, INVALID_DELTA_EXPIRY_TIME));
}

/**
 * @tc.name: GenerateDlpCertificate002
 * @tc.desc: GenerateDlpCertificate test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GenerateDlpCertificate002, TestSize.Level1)
{
    uint32_t threadsNum = 1000;
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < threadsNum; ++i) {
        threads.emplace_back(std::thread(FuzzTest));
    }

    for (auto& thread : threads) {
        thread.join();
    }
    uint32_t waitEndTime = 10;
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
    PermissionPolicy policy;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::ParseDlpCertificate(cert, policy));
    cert = {1, 2, 3};
    ASSERT_EQ(1, DlpPermissionKit::ParseDlpCertificate(cert, policy)); // credential error code 1
}

/**
 * @tc.name: InstallDlpSandbox001
 * @tc.desc: InstallDlpSandbox test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, InstallDlpSandbox001, TestSize.Level1)
{
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: InstallDlpSandbox002
 * @tc.desc: InstallDlpSandbox invalid input.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, InstallDlpSandbox002, TestSize.Level1)
{
    int32_t appIndex = 0;
    ASSERT_NE(DLP_OK, DlpPermissionKit::InstallDlpSandbox("test.test", READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::InstallDlpSandbox("", READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, static_cast<AuthPermType>(100), DEFAULT_USERID, appIndex));
}

/**
 * @tc.name: UninstallDlpSandbox001
 * @tc.desc: UninstallDlpSandbox invalid input.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, UninstallDlpSandbox001, TestSize.Level1)
{
    int32_t appIndex = 1;
    ASSERT_NE(DLP_OK, DlpPermissionKit::UninstallDlpSandbox("test.test", appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::UninstallDlpSandbox("", appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: GetSandboxExternalAuthorization001
 * @tc.desc: GetSandboxExternalAuthorization test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIR1
 */
HWTEST_F(DlpPermissionKitTest, GetSandboxExternalAuthorization001, TestSize.Level1)
{
    // sandboxUid is invalid
    OHOS::AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    ASSERT_NE(DLP_OK, DlpPermissionKit::GetSandboxExternalAuthorization(-1, want, authType));

    // sandboxUid is ok
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    int sandboxUid = GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetSandboxExternalAuthorization(sandboxUid, want, authType));
    ASSERT_TRUE(authType == DENY_START_ABILITY);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));

    // uid is not sandbox
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetSandboxExternalAuthorization(1000, want, authType));
    ASSERT_TRUE(authType == ALLOW_START_ABILITY);
}

/**
 * @tc.name: QueryDlpFileAccessByTokenId001
 * @tc.desc: QueryDlpFileCopyableByTokenId func test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccessByTokenId001, TestSize.Level1)
{
    // query dlp file access with read only sandbox app tokenId
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    AccessTokenID sandboxTokenId = GetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, appIndex);
    bool copyable = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, sandboxTokenId));
    ASSERT_EQ(copyable, false);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));

    // query dlp file access with full control sandbox app tokenId
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    sandboxTokenId = GetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, appIndex);
    copyable = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, sandboxTokenId));
    ASSERT_EQ(copyable, true);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));

    // query dlp file access with normal app tokenId
    AccessTokenID normalTokenId = GetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, 0);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, normalTokenId));
    ASSERT_EQ(copyable, true);
}

/**
 * @tc.name: QueryDlpFileAccessByTokenId002
 * @tc.desc: QueryDlpFileCopyableByTokenId invalid input.
 * @tc.type: FUNC
 * @tc.require:AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccessByTokenId002, TestSize.Level1)
{
    // query dlp file access with invalid tokenId
    bool copyable = false;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, 0));
    ASSERT_EQ(copyable, false);
}

/**
 * @tc.name: QueryDlpFileAccess001
 * @tc.desc: QueryDlpFileCopyable func test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccess001, TestSize.Level1)
{
    // query dlp file access in normal app
    AuthPermType permType;
    setuid(GetAppUid(DLP_MANAGER_APP, 0, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permType));
    ASSERT_EQ(permType, PERM_MAX);
    setuid(g_selfUid);

    // query dlp file access in read only sandbox app
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permType));
    ASSERT_EQ(permType, READ_ONLY);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);

    // query dlp file access in full control sandbox app
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permType));
    ASSERT_EQ(permType, FULL_CONTROL);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);
}

/**
 * @tc.name: IsInDlpSandbox001
 * @tc.desc: IsInDlpSandbox func test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, IsInDlpSandbox001, TestSize.Level1)
{
    // query whether in sandbox in normal app
    bool inSandbox = false;
    setuid(GetAppUid(DLP_MANAGER_APP, 0, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, false);
    setuid(g_selfUid);

    // query whether in sandbox in read only sandbox app
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, true);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);

    // query whether in sandbox in full control sandbox app
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, true);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);
}

/**
 * @tc.name: GetDlpSupportFileType001
 * @tc.desc: GetDlpSupportFileType func test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GetDlpSupportFileType001, TestSize.Level1)
{
    // query support dlp file types in normal app
    std::vector<std::string> supportFileType;
    setuid(GetAppUid(DLP_MANAGER_APP, 0, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);
    setuid(g_selfUid);

    // query support dlp file types in read only sandbox app
    int32_t appIndex = 0;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);

    // query support dlp file types in full control sandbox app
    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, appIndex));
    ASSERT_TRUE(appIndex != 0);
    setuid(GetAppUid(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, appIndex, DEFAULT_USERID));
    setuid(g_selfUid);
}
