/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dlp_file_test.h"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#define private public
#include "dlp_file.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "c_mock_common.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileTest"};

void initDlpFileCiper(DlpFile &testFile)
{
    uint8_t keyData[16] = {};
    struct DlpBlob key = {
        .data = keyData,
        .size = 16
    };

    uint8_t ivData[16] = {};
    struct DlpCipherParam param;
    param.iv.data = ivData;
    param.iv.size = IV_SIZE;
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };

    testFile.SetCipher(key, spec);
}
}

void DlpFileTest::SetUpTestCase() {}

void DlpFileTest::TearDownTestCase() {}

void DlpFileTest::SetUp() {}

void DlpFileTest::TearDown() {}

/**
 * @tc.name: IsValidCipher001
 * @tc.desc: test IsValidChiper error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, IsValidCipher001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValidCipher001");

    struct DlpBlob key = {
        .data = nullptr,
    };

    struct DlpUsageSpec spec;
    uint8_t keyData[DLP_KEY_LEN_256] = { 0 };

    // key.data nullptr
    DlpFile testFile(1000);
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // key size is invalid
    key.data = keyData;
    key.size = 100;
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // key size DLP_KEY_LEN_128, mode is not ctr
    key.size = DLP_KEY_LEN_128;
    spec.mode = 2;
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // key size DLP_KEY_LEN_192, algParam is null
    key.size = DLP_KEY_LEN_192;
    spec.mode = DLP_MODE_CTR;
    spec.algParam = nullptr;
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // key size DLP_KEY_LEN_256, iv size invalid
    key.size = DLP_KEY_LEN_256;
    struct DlpCipherParam algParam;
    uint8_t ivData[IV_SIZE] = { 0 };
    spec.algParam = &algParam;
    spec.algParam->iv.size = 1;
    spec.algParam->iv.data = ivData;
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // key size DLP_KEY_LEN_256, iv data invalid
    key.size = DLP_KEY_LEN_256;
    spec.algParam = &algParam;
    spec.algParam->iv.size = 16;
    spec.algParam->iv.data = nullptr;
    ASSERT_FALSE(testFile.IsValidCipher(key, spec));

    // all valid
    key.size = DLP_KEY_LEN_256;
    spec.algParam = &algParam;
    spec.algParam->iv.size = 16;
    spec.algParam->iv.data = ivData;
    ASSERT_TRUE(testFile.IsValidCipher(key, spec));
}

/**
 * @tc.name: CopyBlobParam001
 * @tc.desc: test copy blob param error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, CopyBlobParam001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CopyBlobParam001");

    DlpFile testFile(1000);
    struct DlpBlob src = {
        .data = nullptr,
    };
    struct DlpBlob dst;

    // src.data null
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.CopyBlobParam(src, dst));

    // src.size 0
    uint8_t data[16] = {0};
    src.data = data;
    src.size = 0;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.CopyBlobParam(src, dst));

    // size > DLP_MAX_CERT_SIZE
    src.size = DLP_MAX_CERT_SIZE + 1;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.CopyBlobParam(src, dst));

    // params ok
    src.size = 16;
    ASSERT_EQ(DLP_OK, testFile.CopyBlobParam(src, dst));
    ASSERT_NE(dst.data, nullptr);
    delete dst.data;
}


/**
 * @tc.name: CleanBlobParam001
 * @tc.desc: test clean blob error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, CleanBlobParam001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CleanBlobParam001");

    DlpFile testFile(1000);
    struct DlpBlob blob = {
        .data = nullptr,
    };

    // blob.data null
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.CleanBlobParam(blob));

    // blob.size 0
    uint8_t* data = new (std::nothrow) uint8_t[16];
    ASSERT_NE(nullptr, data);
    blob.data = data;
    blob.size = 0;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.CleanBlobParam(blob));

    blob.size = 16;
    ASSERT_EQ(DLP_OK, testFile.CleanBlobParam(blob));
}

/**
 * @tc.name: GetLocalAccountName001
 * @tc.desc: test get local account name error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, GetLocalAccountName001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetLocalAccountName001");

    DlpFile testFile(1000);
    std::string account;
    int ret = testFile.GetLocalAccountName(account);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: UpdateDlpFilePermission001
 * @tc.desc: test update dlp permission, current account is owner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, UpdateDlpFilePermission001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFilePermission001");

    DlpFile testFile(1000);
    testFile.policy_.ownerAccount_ = "ohosAnonymousName";
    testFile.authPerm_ = DEFAULT_PERM;

    testFile.UpdateDlpFilePermission();
    ASSERT_EQ(testFile.authPerm_, FULL_CONTROL);
}

/**
 * @tc.name: UpdateDlpFilePermission002
 * @tc.desc: test update dlp permission, current account is in authUser, permission is ReadOnly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, UpdateDlpFilePermission002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFilePermission002");

    DlpFile testFile(1000);
    AuthUserInfo user = {
        .authAccount = "ohosAnonymousName",
        .authPerm = READ_ONLY
    };

    testFile.policy_.authUsers_.emplace_back(user);
    testFile.authPerm_ = DEFAULT_PERM;

    testFile.UpdateDlpFilePermission();
    ASSERT_EQ(testFile.authPerm_, READ_ONLY);
}

/**
 * @tc.name: UpdateDlpFilePermission003
 * @tc.desc: test update dlp permission, current account is in authUser, permission is Full
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, UpdateDlpFilePermission003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFilePermission003");

    DlpFile testFile(1000);
    AuthUserInfo user = {
        .authAccount = "ohosAnonymousName",
        .authPerm = FULL_CONTROL
    };

    testFile.policy_.authUsers_.emplace_back(user);
    testFile.authPerm_ = DEFAULT_PERM;

    testFile.UpdateDlpFilePermission();
    ASSERT_EQ(testFile.authPerm_, FULL_CONTROL);
}

/**
 * @tc.name: UpdateDlpFilePermission004
 * @tc.desc: test update dlp permission, current account is in not authUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, UpdateDlpFilePermission004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFilePermission004");

    DlpFile testFile(1000);
    AuthUserInfo user = {
        .authAccount = "noExistUser",
        .authPerm = FULL_CONTROL
    };

    testFile.policy_.authUsers_.emplace_back(user);
    testFile.authPerm_ = DEFAULT_PERM;
    testFile.UpdateDlpFilePermission();
    ASSERT_EQ(testFile.authPerm_, DEFAULT_PERM);
}

/**
 * @tc.name: SetCipher001
 * @tc.desc: test set cipher invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetCipher001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetCipher001");

    DlpFile testFile(1000);
    struct DlpBlob key = {
        .data = nullptr,
    };
    struct DlpUsageSpec spec;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetCipher(key, spec));
}

/**
 * @tc.name: SetCipher002
 * @tc.desc: test set cipher valid, copy iv fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetCipher002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetCipher001");

    DlpFile testFile(1000);
    uint8_t keyData[DLP_KEY_LEN_256] = { 0 };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { 0 };
    spec.algParam->iv.size = 16;
    spec.algParam->iv.data = ivData;
    spec.mode = DLP_MODE_CTR;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.SetCipher(key, spec));
    CleanMockConditions();
}

/**
 * @tc.name: SetCipher003
 * @tc.desc: test set cipher valid, copy key fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetCipher003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetCipher003");

    DlpFile testFile(1000);
    uint8_t keyData[DLP_KEY_LEN_256] = { 0 };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { 0 };
    spec.algParam->iv.size = 16;
    spec.algParam->iv.data = ivData;
    spec.mode = DLP_MODE_CTR;

    DlpCMockCondition condition;
    condition.mockSequence = { false, true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.SetCipher(key, spec));
    CleanMockConditions();
}

/**
 * @tc.name: SetCipher004
 * @tc.desc: test set cipher valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetCipher004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetCipher004");

    DlpFile testFile(1000);
    uint8_t keyData[DLP_KEY_LEN_256] = { 0 };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { 0 };
    spec.algParam->iv.size = 16;
    spec.algParam->iv.data = ivData;
    spec.mode = DLP_MODE_CTR;
    ASSERT_EQ(DLP_OK, testFile.SetCipher(key, spec));
}

/**
 * @tc.name: SetContactAccount001
 * @tc.desc: test set contact account invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetContactAccount001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetContactAccount001");
    DlpFile testFile(1000);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetContactAccount(""));

    std::string invalidAccount(DLP_MAX_CERT_SIZE + 1, 'a');
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetContactAccount(invalidAccount));

    // head_.certSize = 0
    testFile.head_.certSize = 0;
    ASSERT_EQ(DLP_OK, testFile.SetContactAccount("testAccount"));
}

/**
 * @tc.name: SetPolicy001
 * @tc.desc: test set policy invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetPolicy001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetPolicy001");
    DlpFile testFile(1000);
    PermissionPolicy policy;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetPolicy(policy));
}

/**
 * @tc.name: IsValidDlpHeader001
 * @tc.desc: test dlp file header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, IsValidDlpHeader001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValidDlpHeader001");
    DlpFile testFile(1000);
    PermissionPolicy policy;
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = 0,
        .certSize = 20,
        .contactAccountOffset = sizeof(struct DlpHeader) + 20,
        .contactAccountSize = 20,
        .txtOffset  = sizeof(struct DlpHeader) + 20 + 20,
        .txtSize = 100,
        .offlineCertOffset = 0,
        .offlineCertSize = 0,
    };

    // valid header
    ASSERT_TRUE(testFile.IsValidDlpHeader(header));

    // wrong magic
    header.magic = 0;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
    header.magic = DLP_FILE_MAGIC;

    // certSize 0
    header.certSize = 0;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));

    // certSize too large
    header.certSize = DLP_MAX_CERT_SIZE + 1;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
    header.certSize = 20;

    // certOffset invalid
    header.certOffset = 100;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
    header.certOffset = 20;

    // contactAccountSize 0
    header.contactAccountSize = 0;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));

    // contactAccountSize too large
    header.contactAccountSize = DLP_MAX_CERT_SIZE + 1;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));

    // contactAccountOffset invalid
    header.contactAccountOffset = 100;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
    header.contactAccountOffset = 52;

    // txtOffset invalid
    header.txtOffset = 100;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
    header.txtOffset = 72;

    // txtOffset invalid
    header.txtSize = DLP_MAX_CONTENT_SIZE + 1;
    ASSERT_FALSE(testFile.IsValidDlpHeader(header));
}

/**
 * @tc.name: ParseDlpHeader001
 * @tc.desc: test parse dlp file header failed when file invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader001");
    DlpFile testFile(1000);

    testFile.dlpFd_ = -1;
    ASSERT_EQ(DLP_PARSE_ERROR_FD_ERROR, testFile.ParseDlpHeader());

    testFile.dlpFd_ = 1;
    testFile.isFuseLink_ = true;
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_LINKING, testFile.ParseDlpHeader());

    // fd > 0 but invalid
    testFile.dlpFd_ = 1000;
    testFile.isFuseLink_ = false;
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.ParseDlpHeader());
}

/**
 * @tc.name: ParseDlpHeader002
 * @tc.desc: test parse dlp file header failed when file header too short
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader002");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    DlpFile testFile(fd);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
    };

    // write less than header size
    write(fd, &header, sizeof(header) - 1);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.ParseDlpHeader());
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: ParseDlpHeader003
 * @tc.desc: test parse dlp file header failed when file header invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader003");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    DlpFile testFile(fd);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 0,
        .contactAccountSize = 20,
    };

    // write less than header size
    write(fd, &header, sizeof(header));
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_NOT_DLP, testFile.ParseDlpHeader());
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: ParseDlpHeader004
 * @tc.desc: test parse dlp file header failed when no cert data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader004");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    DlpFile testFile(fd);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = 0,
        .certSize = 20,
        .contactAccountOffset = sizeof(struct DlpHeader) + 20,
        .contactAccountSize = 20,
        .txtOffset  = sizeof(struct DlpHeader) + 20 + 20,
        .txtSize = 100,
        .offlineCertOffset = 0,
        .offlineCertSize = 0,
    };
    write(fd, &header, sizeof(header));

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.ParseDlpHeader());
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: ParseDlpHeader005
 * @tc.desc: test parse dlp file header failed when no contact account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader005");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    DlpFile testFile(fd);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = 0,
        .certSize = 20,
        .contactAccountOffset = sizeof(struct DlpHeader) + 20,
        .contactAccountSize = 20,
        .txtOffset  = sizeof(struct DlpHeader) + 20 + 20,
        .txtSize = 100,
        .offlineCertOffset = 0,
        .offlineCertSize = 0,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[20] = {0};
    write(fd, buffer, 20);

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.ParseDlpHeader());
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: ParseDlpHeader006
 * @tc.desc: test parse dlp file header success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, ParseDlpHeader006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpHeader006");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    DlpFile testFile(fd);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = 0,
        .certSize = 20,
        .contactAccountOffset = sizeof(struct DlpHeader) + 20,
        .contactAccountSize = 20,
        .txtOffset  = sizeof(struct DlpHeader) + 20 + 20,
        .txtSize = 100,
        .offlineCertOffset = 0,
        .offlineCertSize = 0,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[40] = {0};
    write(fd, buffer, 40);

    EXPECT_EQ(DLP_OK, testFile.ParseDlpHeader());
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: SetEncryptCert001
 * @tc.desc: test set encrypt cert params invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetEncryptCert001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert001");

    DlpFile testFile(1000);
    struct DlpBlob cert = {
        .data = nullptr,
        .size = 0
    };
    // size = 0
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetEncryptCert(cert));

    // size too large
    uint8_t data[16] = {};
    cert.data = data;
    cert.size = DLP_MAX_CERT_SIZE + 1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetEncryptCert(cert));
}

/**
 * @tc.name: SetEncryptCert002
 * @tc.desc: test set encrypt cert when cert has exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetEncryptCert002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert002");

    DlpFile testFile(1000);
    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = 32
    };
    uint8_t *oldCert = new (std::nothrow) uint8_t[16];
    testFile.cert_.data = oldCert;
    testFile.cert_.size = 16;
    ASSERT_NE(testFile.cert_.data, nullptr);

    EXPECT_EQ(DLP_OK, testFile.SetEncryptCert(cert));
    EXPECT_NE(oldCert, testFile.cert_.data);
}

/**
 * @tc.name: SetEncryptCert003
 * @tc.desc: test set encrypt cert when copy blob fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, SetEncryptCert003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert003");

    DlpFile testFile(1000);
    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = 0
    };

    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.SetEncryptCert(cert));
}

/**
 * @tc.name: DupUsageSpec001
 * @tc.desc: test DupUsageSpec when spec is not initial
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DupUsageSpec001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DupUsageSpec001");

    DlpFile testFile(1000);
    struct DlpUsageSpec spec;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DupUsageSpec(spec));
}

/**
 * @tc.name: DupUsageSpec002
 * @tc.desc: test DupUsageSpec when memcpy_s failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DupUsageSpec002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DupUsageSpec002");

    DlpFile testFile(1000);
    uint8_t data[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = data,
            .size = 16
        }
    };
    struct DlpUsageSpec specOld = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = specOld;

    struct DlpUsageSpec spec;
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.DupUsageSpec(spec));
    CleanMockConditions();
}

/**
 * @tc.name: DupUsageSpec003
 * @tc.desc: test DupUsageSpec ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DupUsageSpec003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DupUsageSpec003");

    DlpFile testFile(1000);
    uint8_t data[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = data,
            .size = 16
        }
    };
    struct DlpUsageSpec specOld = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = specOld;

    struct DlpUsageSpec spec;
    ASSERT_EQ(DLP_OK, testFile.DupUsageSpec(spec));
    ASSERT_EQ(DLP_MODE_CTR, spec.mode);
    ASSERT_NE(nullptr, spec.algParam);
    ASSERT_EQ(16, spec.algParam->iv.size);
    ASSERT_NE(nullptr, spec.algParam->iv.data);
}

/**
 * @tc.name: DoDlpBlockCryptOperation001
 * @tc.desc: test DoDlpBlockCryptOperation params invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpBlockCryptOperation001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpBlockCryptOperation001");

    DlpFile testFile(1000);

    uint8_t data1[16] = {};
    uint8_t data2[16] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = 16
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = 16
    };

    // offset not aligned
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DoDlpBlockCryptOperation(message1, message2, 1, false));

    // message1 data nullptr
    message1.data = nullptr;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
    message1.data = data1;

    // message1 size 0
    message1.size = 0;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
    message1.size = 16;

    // message2 data nullptr
    message2.data = nullptr;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
    message2.data = data1;

    // message2 size 0
    message2.size = 0;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
    message2.size = 16;
}

/**
 * @tc.name: DoDlpBlockCryptOperation002
 * @tc.desc: test DoDlpBlockCryptOperation cipher invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpBlockCryptOperation002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpBlockCryptOperation002");

    DlpFile testFile(1000);

    uint8_t data1[16] = {};
    uint8_t data2[16] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = 16
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = 16
    };

    testFile.cipher_.usageSpec.algParam = nullptr;
    ASSERT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
}

/**
 * @tc.name: DoDlpBlockCryptOperation003
 * @tc.desc: test DoDlpBlockCryptOperation when DlpOpensslAesEncrypt fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpBlockCryptOperation003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpBlockCryptOperation003");

    DlpFile testFile(1000);

    uint8_t data1[16] = {};
    uint8_t data2[16] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = 16
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = 16
    };

    uint8_t ivData[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = 16
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    ASSERT_EQ(DLP_PARSE_ERROR_CRYPT_FAIL, testFile.DoDlpBlockCryptOperation(message1, message2, 16, false));
}

/**
 * @tc.name: DoDlpContentCryptyOperation001
 * @tc.desc: test DoDlpBlockCryptOperation when read fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpContentCryptyOperation001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpContentCryptyOperation001");

    DlpFile testFile(1000);
    uint8_t ivData[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = 16
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCryptyOperation(1000, 1000, 0, 10, true));
}

/**
 * @tc.name: DoDlpContentCryptyOperation002
 * @tc.desc: test DoDlpBlockCryptOperation when crypt operation failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpContentCryptyOperation002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpContentCryptyOperation002");
    DlpFile testFile(1000);
    uint8_t ivData[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = 16
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[40] = {1};
    write(fd, buffer, 40);
    lseek(fd, 0, SEEK_SET);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPT_FAIL, testFile.DoDlpContentCryptyOperation(fd, 1000, 0, 10, true));
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: DoDlpContentCryptyOperation003
 * @tc.desc: test DoDlpBlockCryptOperation when write to dlpfile failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpContentCryptyOperation003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpContentCryptyOperation003");
    DlpFile testFile(1000);

    initDlpFileCiper(testFile);

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[40] = {1};
    write(fd, buffer, 40);
    lseek(fd, 0, SEEK_SET);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCryptyOperation(fd, 1000, 0, 10, true));
    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: GenFile001
 * @tc.desc: test gen file params invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, GenFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenFile001");
    DlpFile testFile(1000);

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.GenFile(-1));

    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.GenFile(1));

    testFile.dlpFd_ = 1000;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.GenFile(1));
}

/**
 * @tc.name: GenFile002
 * @tc.desc: test gen file when io api exception
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, GenFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenFile002");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("ftruncate", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.GenFile(fdPlain));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: RemoveDlpPermission001
 * @tc.desc: test remove dlp permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, RemoveDlpPermission001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RemoveDlpPermission001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    // isFuseLink_ true
    testFile.isFuseLink_ = true;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_LINKING, testFile.RemoveDlpPermission(fdPlain));
    testFile.isFuseLink_ = false;

    // authPerm_ READ_ONLY
    testFile.authPerm_ = READ_ONLY;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, testFile.RemoveDlpPermission(fdPlain));
    testFile.authPerm_ = FULL_CONTROL;

    // outPlainFileFd invalid
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, testFile.RemoveDlpPermission(-1));

    // dlpFd invalid
    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, testFile.RemoveDlpPermission(fdPlain));
    testFile.dlpFd_ = fdDlp;

    // cipher invalid
    testFile.cipher_.encKey.size = 0;
    EXPECT_EQ(DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID, testFile.RemoveDlpPermission(fdPlain));
    testFile.cipher_.encKey.size = 16;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.RemoveDlpPermission(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("ftruncate", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.RemoveDlpPermission(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.RemoveDlpPermission(fdPlain));
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.RemoveDlpPermission(fdPlain));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DlpFileRead001
 * @tc.desc: test dlp file read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DlpFileRead001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpFileRead001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    // isFuseLink_ true
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, nullptr, 10));

    uint8_t buffer[16] = {};
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 0));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(DLP_MAX_CONTENT_SIZE, buffer, 1));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, DLP_FUSE_MAX_BUFFLEN + 1));

    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 16));
    testFile.dlpFd_ = fdDlp;

    testFile.cipher_.encKey.size = 0;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 16));
    testFile.cipher_.encKey.size = 16;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DlpFileRead(0, buffer, 16));
    CleanMockConditions();

    // read size 0
    EXPECT_EQ(0, testFile.DlpFileRead(0, buffer, 16));

    // do crypt failed
    write(fdDlp, "1111", 4);
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DlpFileRead(0, buffer, 16));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.DlpFileRead(0, buffer, 16));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: WriteFirstBlockData001
 * @tc.desc: test write dlp file first block
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, WriteFirstBlockData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "WriteFirstBlockData001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[16] = {0x1};

    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    testFile.dlpFd_ = fdDlp;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    // decrypt fail
    write(fdDlp, "1111", 4);
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPT_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    // encrypt fail
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { false, true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPT_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    // lseek fail
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    // write fail
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DoDlpFileWrite001
 * @tc.desc: test do dlp file write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpFileWrite001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpFileWrite001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[18] = {0x1};

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    condition.mockSequence = { true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    condition.mockSequence = { true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPT_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    condition.mockSequence = { false, true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: GetFsContentSize001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, GetFsContentSize001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetFsContentSize001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = 16;
    EXPECT_EQ(INVALID_FILE_SIZE, testFile.GetFsContentSize());

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: UpdateDlpFileContentSize001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, UpdateDlpFileContentSize001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFileContentSize001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = 16;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.UpdateDlpFileContentSize());
    testFile.head_.txtOffset = 0;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.UpdateDlpFileContentSize());
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.UpdateDlpFileContentSize());
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: FillHoleData001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, FillHoleData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FillHoleData001");
    DlpFile testFile(-1);
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.FillHoleData(0, 16));
}

/**
 * @tc.name: DlpFileWrite001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DlpFileWrite001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpFileWrite001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[16] = {0x1};

    testFile.head_.txtOffset = 0;

    testFile.authPerm_ = READ_ONLY;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, testFile.DlpFileWrite(4, writeBuffer, 16));
    testFile.authPerm_ = FULL_CONTROL;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, nullptr, 16));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 0));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(DLP_MAX_CONTENT_SIZE, writeBuffer, 1));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, DLP_FUSE_MAX_BUFFLEN + 1));

    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 16));
    testFile.dlpFd_ = fdDlp;

    testFile.cipher_.encKey.size = 0;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 16));
    testFile.cipher_.encKey.size = 16;

    // fill hole data fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DlpFileWrite(16, writeBuffer, 16));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: Truncate001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, Truncate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "Truncate001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);
    DlpFile testFile(fdDlp);
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = 0;

    testFile.authPerm_ = READ_ONLY;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, testFile.Truncate(16));
    testFile.authPerm_ = FULL_CONTROL;

    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.Truncate(16));
    testFile.dlpFd_ = fdDlp;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.Truncate(0xffffffff));

    EXPECT_EQ(DLP_OK, testFile.Truncate(0));

    // fill hole data fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.Truncate(16));
    CleanMockConditions();
    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DoDlpContentCopyOperation001
 * @tc.desc: DoDlpContentCopyOperation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileTest, DoDlpContentCopyOperation001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DoDlpContentCopyOperation001");
    DlpFile testFile(1000);
    uint8_t ivData[16] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = 16
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCopyOperation(0, 0, 100, 10));
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCopyOperation(0, 0, 10, 100));
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[40] = {1};
    write(fd, buffer, 40);
    lseek(fd, 0, SEEK_SET);
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCopyOperation(fd, 0, 10, 100));
    int fd2 = open("/data/fuse_test2.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd2, -1);
    ASSERT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpContentCopyOperation(fd, fd2, 10, 100));
}