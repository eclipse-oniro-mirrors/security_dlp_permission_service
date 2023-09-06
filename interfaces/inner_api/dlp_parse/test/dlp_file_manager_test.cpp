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

#include "dlp_file_manager_test.h"
#include "c_mock_common.h"
#define private public
#include "dlp_file_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include <cstdio>
#include <cstring>
#include <fcntl.h>

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileManagerTest"};
static int g_fdDlp = -1;
}

void DlpFileManagerTest::SetUpTestCase() {}

void DlpFileManagerTest::TearDownTestCase()
{
    if (g_fdDlp != -1) {
        close(g_fdDlp);
        unlink("/data/fuse_test_dlp.txt");
    }
}

void DlpFileManagerTest::SetUp() {}

void DlpFileManagerTest::TearDown() {}

/**
 * @tc.name: OperDlpFileNode001
 * @tc.desc: test add/remove/get dlp file node.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OperDlpFileNode001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OperDlpFileNode001");

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1);
    ASSERT_NE(filePtr, nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_ALREADY_OPENED);
    EXPECT_NE(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_NOT_OPENED);
}

/**
 * @tc.name: OperDlpFileNode002
 * @tc.desc: test add too many dlp file nodes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OperDlpFileNode002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OperDlpFileNode002");

    std::shared_ptr<DlpFile> openDlpFiles[1000];

    for (int i = 0; i < 1000; i++) {
        std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(i);
        openDlpFiles[i] = filePtr;
        EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_OK);
    }

    std::shared_ptr<DlpFile> filePtr1 = std::make_shared<DlpFile>(1001);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr1), DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE);

    for (int i = 0; i < 1000; i++) {
        EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(openDlpFiles[i]), DLP_OK);
    }
}

/**
 * @tc.name: GenerateCertData001
 * @tc.desc: Generate cert data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateCertData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateCertData001");

    PermissionPolicy policy;
    struct DlpBlob certData;
    EXPECT_EQ(DlpFileManager::GetInstance().GenerateCertData(policy, certData), DLP_SERVICE_ERROR_VALUE_INVALID);

    policy.aeskey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.aeskey_, nullptr);
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.iv_, nullptr);
    policy.ivLen_ = 16;
    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    policy.ownerAccount_ = std::string(DLP_MAX_CERT_SIZE + 1, 'a');
    EXPECT_EQ(DlpFileManager::GetInstance().GenerateCertData(policy, certData), DLP_PARSE_ERROR_VALUE_INVALID);

    policy.ownerAccount_ = "test";
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, DlpFileManager::GetInstance().GenerateCertData(policy, certData));
    CleanMockConditions();
}

/**
 * @tc.name: PrepareDlpEncryptParms001
 * @tc.desc: test prepare dlp encrypt params error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, PrepareDlpEncryptParms001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "PrepareDlpEncryptParms001");

    PermissionPolicy policy;
    policy.aeskey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.aeskey_, nullptr);
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.iv_, nullptr);
    policy.ivLen_ = 16;
    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    policy.ownerAccount_ = "test";
    struct DlpBlob key;
    struct DlpUsageSpec usage;
    struct DlpBlob certData;

    // key create fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData));
    CleanMockConditions();

    // iv create fail
    condition.mockSequence = { false, true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData));
    CleanMockConditions();

    // create cert data failed with memcpy_s fail
    condition.mockSequence = { false, false, true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData));
    CleanMockConditions();
}

/**
 * @tc.name: ParseDlpFileFormat001
 * @tc.desc: test parse dlp file format error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFileContentSize001");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp);
    ASSERT_NE(filePtr, nullptr);

    filePtr->dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, ""));
    filePtr->dlpFd_ = g_fdDlp;

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 64,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 32,
        .contactAccountOffset = sizeof(struct DlpHeader) + 32,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    uint8_t buffer[64] = {0};
    write(g_fdDlp, buffer, 64);
    lseek(g_fdDlp, 0, SEEK_SET);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, ""));

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: ParseDlpFileFormat002
 * @tc.desc: test parse dlp file formate error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpFileFormat002");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp);
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 256 + 32,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 256,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountType\":0}";
    write(g_fdDlp, certStr.c_str(), certStr.length());
    lseek(g_fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(g_fdDlp, buffer, 32);

    lseek(g_fdDlp, 0, SEEK_SET);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, ""));

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: ParseDlpFileFormat003
 * @tc.desc: test parse dlp file formate error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpFileFormat003");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp);
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 256 + 32,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 256,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountType\":1}";
    write(g_fdDlp, certStr.c_str(), certStr.length());
    lseek(g_fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(g_fdDlp, buffer, 32);

    lseek(g_fdDlp, 0, SEEK_SET);

    // make SetCipher failed
    DlpCMockCondition condition;
    condition.mockSequence = { false, false, false, false, false, false, false, true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, ""));
    CleanMockConditions();

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: FreeChiperBlob001
 * @tc.desc: test free chiper blob abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, FreeChiperBlob001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FreeChiperBlob001");
    struct DlpBlob key = {
        .data = nullptr,
        .size = 0
    };
    struct DlpBlob certData = {
        .data = nullptr,
        .size = 0
    };

    struct DlpUsageSpec spec = {
        .algParam = nullptr
    };

    // algparm nullptr
    DlpFileManager::GetInstance().FreeChiperBlob(key, certData, spec);

    // algparm iv nullptr
    spec.algParam = new (std::nothrow) struct DlpCipherParam;
    ASSERT_NE(spec.algParam, nullptr);
    spec.algParam->iv.data = nullptr;
    DlpFileManager::GetInstance().FreeChiperBlob(key, certData, spec);

    ASSERT_EQ(spec.algParam, nullptr);
}

/**
 * @tc.name: SetDlpFileParams001
 * @tc.desc: test set dlp file params with prepare ciper failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams001");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // PrepareDlpEncryptParms fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();

    // SetCipher fail
    property.ownerAccount = "owner";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    condition.mockSequence = { false, false, true};
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();
}

/**
 * @tc.name: SetDlpFileParams002
 * @tc.desc: test set dlp file params with set policy failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams002");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
}

/**
 * @tc.name: SetDlpFileParams003
 * @tc.desc: test set dlp file params with set cert failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams003");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "owner";
    property.contractAccount = "account";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    DlpCMockCondition condition;
    condition.mockSequence = {
        false, false, false, false, false, false,
        false, false, false, false, true
    };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();
}

/**
 * @tc.name: SetDlpFileParams004
 * @tc.desc: test set dlp file params with contact account empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams004");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "owner";
    property.contractAccount = "";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();
}

/**
 * @tc.name: GenerateDlpFile001
 * @tc.desc: test generate dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile001");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;
    property.ownerAccount = "owner";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().GenerateDlpFile(-1, 1000, property, filePtr));

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, -1, property, filePtr));

    DlpFileManager::GetInstance().AddDlpFileNode(filePtr);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_ALREADY_OPENED,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr));
    DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr);
}

/**
 * @tc.name: GenerateDlpFile002
 * @tc.desc: test set dlp file params with wrong property
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile002");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr));
}

/**
 * @tc.name: GenerateDlpFile003
 * @tc.desc: test set dlp file params with generate real file failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile003");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "owner";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr));
}

/**
 * @tc.name: OpenDlpFile001
 * @tc.desc: test set dlp file params with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OpenDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OpenDlpFile001");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "owner";
    property.contractAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().OpenDlpFile(-1, filePtr, ""));

    std::shared_ptr<DlpFile> filePtr1 = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr1, nullptr);
    DlpFileManager::GetInstance().AddDlpFileNode(filePtr1);

    EXPECT_EQ(DLP_OK,
        DlpFileManager::GetInstance().OpenDlpFile(1000, filePtr, ""));
    EXPECT_EQ(filePtr1, filePtr);
    DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr1);

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        DlpFileManager::GetInstance().OpenDlpFile(1000, filePtr, ""));
}

/**
 * @tc.name: IsDlpFile001
 * @tc.desc: test check IsDlpFile with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, IsDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsDlpFile001");
    bool isDlpFile = false;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().IsDlpFile(-1, isDlpFile));
    EXPECT_FALSE(isDlpFile);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    DlpFileManager::GetInstance().AddDlpFileNode(filePtr);

    EXPECT_EQ(DLP_OK,
        DlpFileManager::GetInstance().IsDlpFile(1000, isDlpFile));
    EXPECT_TRUE(isDlpFile);
    DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr);

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        DlpFileManager::GetInstance().IsDlpFile(1000, isDlpFile));
    EXPECT_FALSE(isDlpFile);
}

/**
 * @tc.name: CloseDlpFile001
 * @tc.desc: test close dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, CloseDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CloseDlpFile001");
    EXPECT_EQ(DLP_PARSE_ERROR_PTR_NULL,
        DlpFileManager::GetInstance().CloseDlpFile(nullptr));
}

/**
 * @tc.name: RecoverDlpFile001
 * @tc.desc: test close dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, RecoverDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RecoverDlpFile001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DLP_PARSE_ERROR_PTR_NULL,
        DlpFileManager::GetInstance().RecoverDlpFile(filePtr, 1000));

    filePtr = std::make_shared<DlpFile>(1000);
    ASSERT_NE(filePtr, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().RecoverDlpFile(filePtr, -1));
}
