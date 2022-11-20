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
}

void DlpFileManagerTest::SetUpTestCase() {}

void DlpFileManagerTest::TearDownTestCase() {}

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
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_ALREADY_OPENED);
    EXPECT_NE(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_NOT_OPENED);
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
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
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
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
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
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(fdDlp);

    filePtr->dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr));
    filePtr->dlpFd_ = fdDlp;

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

    write(fdDlp, &header, sizeof(struct DlpHeader));
    uint8_t buffer[64] = {0};
    write(fdDlp, buffer, 64);
    lseek(fdDlp, 0, SEEK_SET);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr));

    close(fdDlp);
    unlink("/data/fuse_test_dlp.txt");
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
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(fdDlp);
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

    write(fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountType\":0}";
    write(fdDlp, certStr.c_str(), certStr.length());
    lseek(fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(fdDlp, buffer, 32);

    lseek(fdDlp, 0, SEEK_SET);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr));

    close(fdDlp);
    unlink("/data/fuse_test_dlp.txt");
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
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(fdDlp);
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

    write(fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountType\":1}";
    write(fdDlp, certStr.c_str(), certStr.length());
    lseek(fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(fdDlp, buffer, 32);

    lseek(fdDlp, 0, SEEK_SET);

    // make SetCipher failed
    DlpCMockCondition condition;
    condition.mockSequence = { false, false, false, false, false, false, false, true };
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL,
        DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr));
    CleanMockConditions();

    close(fdDlp);
    unlink("/data/fuse_test_dlp.txt");
}
