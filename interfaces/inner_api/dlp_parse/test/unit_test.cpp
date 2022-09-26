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

#include "unit_test.h"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "accesstoken_kit.h"
#include "base_object.h"
#include "dlp_crypt.h"
#include "dlp_file_kits.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "token_setproc.h"
#include "want_params_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpParseUnitTest;
using namespace OHOS::Security::DlpPermission;
using namespace std;
using namespace OHOS::Security::AccessToken;

using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
using WantParamWrapper = OHOS::AAFwk::WantParamWrapper;
using String = OHOS::AAFwk::String;
using Integer = OHOS::AAFwk::Integer;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpParseUnitTest"};
static const int32_t DEFAULT_USERID = 100;
static AccessTokenID g_selfTokenId = 0;

uint8_t g_key[32] = { 0xdc, 0x7c, 0x8d, 0xe, 0xeb, 0x41, 0x4b, 0xb0, 0x8e, 0x24, 0x8, 0x32, 0xc7, 0x88, 0x96, 0xb6,
    0x2, 0x69, 0x65, 0x49, 0xaf, 0x3c, 0xa7, 0x8f, 0x38, 0x3d, 0xe3, 0xf1, 0x23, 0xb6, 0x22, 0xfb };
uint8_t g_iv[16] = { 0x90, 0xd5, 0xe2, 0x45, 0xaa, 0xeb, 0xa0, 0x9, 0x61, 0x45, 0xd1, 0x48, 0x4a, 0xaf, 0xc9, 0xf9 };

static int g_dlpFileFd = -1;
static const std::string PLAIN_FILE_NAME = "/data/fuse_test.txt";
static const std::string DLP_FILE_NAME = "/data/fuse_test.txt.dlp";
static const int DLP_FILE_PERMISSION = 0777;
static const int ENC_BUF_LEN = 10 * 1024 * 1024;

static void CreateDlpFileFd()
{
    int plainFileFd = open(PLAIN_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    g_dlpFileFd = open(DLP_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    if (plainFileFd < 0 || g_dlpFileFd < 0) {
        cout << "create dlpFile fd failed" << endl;
        return;
    }

    struct DlpProperty prop;
    prop.ownerAccount = "ohosAnonymousName";
    prop.ownerAccountType = CLOUD_ACCOUNT;
    prop.contractAccount = "test@test.com";

    std::shared_ptr<DlpFile> filePtr;
    int ret = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, g_dlpFileFd, prop, filePtr);
    close(plainFileFd);
    if (ret != DLP_OK) {
        cout << "create dlpFile object failed" << endl;
        return;
    }
    DlpFileManager::GetInstance().CloseDlpFile(filePtr);
}
}

void DlpParseUnitTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, "com.ohos.dlpmanager", 0);
    SetSelfTokenID(tokenId);
    CreateDlpFileFd();
}

void DlpParseUnitTest::TearDownTestCase()
{
    if (g_dlpFileFd != -1) {
        close(g_dlpFileFd);
    }
    SetSelfTokenID(g_selfTokenId);
}

void DlpParseUnitTest::SetUp() {}

void DlpParseUnitTest::TearDown() {}

void DlpParseUnitTest::CreateDataFile() const
{
    cout << "create Data file" << endl;
}

static void dumpptr(uint8_t *ptr, uint32_t len)
{
    uint8_t *abc = ptr;
    for (uint32_t i = 0; i < len; i++) {
        printf("%x ", *abc);
        abc++;
    }
    printf("\n");
}

/**
 * @tc.name: DlpOpensslAesEncrypt001
 * @tc.desc: Dlp encrypt test with invalid key.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt001");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // key = nullptr
    int32_t ret = DlpOpensslAesEncrypt(nullptr, &usageSpec, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt002
 * @tc.desc: Dlp encrypt test with invalid usageSpec.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt002");

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt003
 * @tc.desc: Dlp encrypt test with invalid message.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt003");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob cipherText = {15, enc};

    // message = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt004
 * @tc.desc: Dlp encrypt test with invalid cipherText.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt004");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob key = {32, g_key};

    // cipherText = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt001
 * @tc.desc: Dlp encrypt test with invalid key.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt001");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // key = nullptr
    int32_t ret = DlpOpensslAesDecrypt(nullptr, &usageSpec, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt002
 * @tc.desc: Dlp encrypt test with invalid usageSpec.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt002");

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, nullptr, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt003
 * @tc.desc: Dlp encrypt test with invalid message.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt003");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob plainText = {15, enc};

    // message = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, nullptr, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt004
 * @tc.desc: Dlp encrypt test with invalid plainText.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt004");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    struct DlpBlob key = {32, g_key};

    // plainText = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit001
 * @tc.desc: Dlp aes init test with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit001");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    // *cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(nullptr, &key, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit002
 * @tc.desc: Dlp aes init test with invalid key
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit002");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    void* ctx = nullptr;

    // key = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, nullptr, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit003
 * @tc.desc: Dlp aes init test with invalid usageSpec
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptInit003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit003");
    void* ctx = nullptr;
    struct DlpBlob key = {32, g_key};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate001
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptUpdate(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate002
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslAesEncryptUpdate(ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate003
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptUpdate003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // cipherText = nullptr
    ret = DlpOpensslAesEncryptUpdate(ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal001
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptFinal(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);

    // cryptoCtx.append = nullptr
    DlpOpensslAesCtx* cryptoCtx = reinterpret_cast<DlpOpensslAesCtx*>(calloc(1, sizeof(DlpOpensslAesCtx)));
    ASSERT_NE(nullptr, cryptoCtx);
    cryptoCtx->mode = DLP_MODE_CTR;
    cryptoCtx->padding = OPENSSL_CTX_PADDING_ENABLE;
    cryptoCtx->append = nullptr;
    ret = DlpOpensslAesEncryptFinal(reinterpret_cast<void**>(&cryptoCtx), &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    free(cryptoCtx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal002
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslAesEncryptFinal(&ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal003
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptFinal003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // cipherText = nullptr
    ret = DlpOpensslAesEncryptFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit001
 * @tc.desc: Dlp aes init test with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit001");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    // *cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(nullptr, &key, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit002
 * @tc.desc: Dlp aes init test with invalid key
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit002");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    void* ctx = nullptr;

    // key = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, nullptr, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit003
 * @tc.desc: Dlp aes init test with invalid usageSpec
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptInit003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit003");
    void* ctx = nullptr;
    struct DlpBlob key = {32, g_key};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate001
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob plainText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptUpdate(nullptr, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate002
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslAesDecryptUpdate(ctx, nullptr, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate003
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid plainText
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptUpdate003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // plainText = nullptr
    ret = DlpOpensslAesDecryptUpdate(ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal001
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptFinal(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal002
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslAesDecryptFinal(&ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal003
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesDecryptFinal003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // cipherText = nullptr
    ret = DlpOpensslAesDecryptFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt001
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptAndDecrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt001");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    int32_t ret;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mEnc = {
        .data = nullptr,
        .size = 15
    };
    mEnc.data = enc;
    struct DlpBlob mDec = {
        .data = nullptr,
        .size = 15
    };
    mDec.data = dec;
    ret = DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    ret = DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec);
    cout << "input hexdump:";
    dumpptr(input, 16);
    cout << "enc hexdump:";
    dumpptr(enc, 16);
    cout << "output hexdump:";
    dumpptr(dec, 16);
    ret = strcmp(reinterpret_cast<char *>(input), reinterpret_cast<char *>(dec));
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt002
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptAndDecrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt002");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    int32_t ret;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mEnc = {
        .data = nullptr,
        .size = 15
    };
    mEnc.data = enc;
    struct DlpBlob mDec = {
        .data = nullptr,
        .size = 15
    };
    mDec.data = dec;

    struct DlpBlob mNull = {
        .data = nullptr,
        .size = 0
    };
    void *ctx;
    int i = 0;

    cout << "input hexdump:";
    dumpptr(input, 16);
    ret = DlpOpensslAesEncryptInit(&ctx, &key, &usage);
    mIn.size = 1;
    mEnc.size = 1;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &mIn, &mEnc);
        mIn.data = mIn.data + 1;
        mEnc.data = mEnc.data + 1;
        i++;
    }
    ret = DlpOpensslAesEncryptFinal(&ctx, &mNull, &mEnc);
    DlpOpensslAesHalFreeCtx(&ctx);

    cout << "enc hexdump:";
    dumpptr(enc, 16);
    ret = DlpOpensslAesDecryptInit(&ctx, &key, &usage);
    i = 0;
    mEnc.data = enc;
    mEnc.size = 1;
    mDec.size = 1;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &mEnc, &mDec);
        mEnc.data = mEnc.data + 1;
        mDec.data = mDec.data + 1;
        i++;
    }
    ret = DlpOpensslAesDecryptFinal(&ctx, &mNull, &mDec);
    DlpOpensslAesHalFreeCtx(&ctx);
    cout << "output hexdump:";
    dumpptr(dec, 16);
    ret = strcmp(reinterpret_cast<char *>(input), reinterpret_cast<char *>(dec));
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt003
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptAndDecrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt003");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    int32_t ret;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t *input = (uint8_t *)malloc(ENC_BUF_LEN);
    uint8_t *enc = (uint8_t *)malloc(ENC_BUF_LEN);
    uint8_t *dec = (uint8_t *)malloc(ENC_BUF_LEN);

    struct DlpBlob mIn = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mIn.data = input;
    struct DlpBlob mEnc = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mEnc.data = enc;
    struct DlpBlob mDec = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mDec.data = dec;

    const static long USEC_PER_SEC = 1000000L;
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);

    ret = DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtimeUs = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "10M date encrypt time use: " << runtimeUs << "(us) " << std::endl;

    gettimeofday(&start, nullptr);
    ret = DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec);
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    runtimeUs = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "10M date decrypt time use: " << runtimeUs << "(us) " << std::endl;
    ASSERT_EQ(0, ret);
    free(input);
    free(enc);
    free(dec);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt004
 * @tc.desc: Dlp encrypt && decrypt test with invalid args.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslAesEncryptAndDecrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt004");
    int32_t ret;

    ret = DlpOpensslAesEncrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    ret = DlpOpensslAesDecrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash001
 * @tc.desc: HASH test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHash001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mOut = {
        .data = nullptr,
        .size = 64
    };
    mOut.data = out;
    int ret;

    ret = DlpOpensslHash(DLP_DIGEST_SHA256, &mIn, &mOut);
    cout << "sha256:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    mOut.size = 64;
    ret = DlpOpensslHash(DLP_DIGEST_SHA384, &mIn, &mOut);
    cout << "sha384:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    mOut.size = 64;
    ret = DlpOpensslHash(DLP_DIGEST_SHA512, &mIn, &mOut);
    cout << "sha512:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslHash002
 * @tc.desc: DlpOpensslHash with invalid alg
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHash002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash002");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[32] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {32, out};

    // alg = 0
    int32_t ret = DlpOpensslHash(DLP_DIGEST_NONE, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);

    // alg != DLP_DIGEST_SHA256 | DLP_DIGEST_SHA384 | DLP_DIGEST_SHA512
    ret = DlpOpensslHash(100, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash003
 * @tc.desc: DlpOpensslHash with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHash003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash003");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {64, out};

    // message = nullptr
    int32_t ret = DlpOpensslHash(DLP_DIGEST_SHA512, nullptr, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash004
 * @tc.desc: DlpOpensslHash with invalid hash
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHash004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash004");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {64, out};

    // hash = nullptr
    int32_t ret = DlpOpensslHash(DLP_DIGEST_SHA512, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashInit001
 * @tc.desc: DlpOpensslHashInit with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashInit001");

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashInit(nullptr, DLP_DIGEST_SHA256);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashInit002
 * @tc.desc: DlpOpensslHashInit with invalid alg
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashInit002");

    // alg = DLP_DIGEST_NONE
    void* ctx = nullptr;
    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_NONE);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);

    // alg = 100
    ctx = nullptr;
    ret = DlpOpensslHashInit(&ctx, 100);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashUpdate001
 * @tc.desc: DlpOpensslHashUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashUpdate001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashUpdate(nullptr, &message);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashUpdate002
 * @tc.desc: DlpOpensslHashUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashUpdate002");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslHashUpdate(ctx, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal001
 * @tc.desc: DlpOpensslHashFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {64, out};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashFinal(nullptr, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashFinal002
 * @tc.desc: DlpOpensslHashFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal002");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslHashFinal(&ctx, nullptr, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal004
 * @tc.desc: DlpOpensslHashFinal with invalid hash
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashFinal004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal004");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    // hash = nullptr
    ret = DlpOpensslHashFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashTest001
 * @tc.desc: split hash test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslHashTest001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashTest001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mOut = {
        .data = nullptr,
        .size = 15
    };
    mOut.data = out;
    struct DlpBlob mNull = {
        .data = nullptr,
        .size = 0
    };
    int i = 0;
    int ret;
    void *ctx;

    ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    ASSERT_EQ(0, ret);

    mIn.size = 1;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &mIn);
        ASSERT_EQ(0, ret);
        mIn.data = mIn.data + 1;
        i++;
    }
    ret = DlpOpensslHashFinal(&ctx, &mNull, &mOut);
    ASSERT_EQ(0, ret);
    DlpOpensslHashFreeCtx(&ctx);

    cout << "sha256sum:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey001
 * @tc.desc: random generate test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslGenerateRandomKey001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey001");
    int ret = 0;
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 32
    };

    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(mIn.data, 16);
    free(mIn.data);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_192, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(mIn.data, 16);
    free(mIn.data);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_128, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(mIn.data, 16);
    free(mIn.data);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey002
 * @tc.desc: random generate test with invalid keySize
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslGenerateRandomKey002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey002");
    struct DlpBlob key = {32, nullptr};
    int32_t ret = DlpOpensslGenerateRandomKey(1, &key);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey003
 * @tc.desc: random generate test with invalid key
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpParseUnitTest, DlpOpensslGenerateRandomKey003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey003");

    // key = nullptr
    int32_t ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: GetSandboxFlag001
 * @tc.desc: Get Sandbox flag, want valid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag001");
    OHOS::AAFwk::Want want;

    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_TRUE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag002
 * @tc.desc: Get Sandbox flag, action inValid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag002");
    OHOS::AAFwk::Want want;
    want.SetAction("ohos.want.action.home");

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag003
 * @tc.desc: Get Sandbox flag, no fileName param
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag003");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag004
 * @tc.desc: Get Sandbox flag, file name is not dlp
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag004");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag005
 * @tc.desc: Get Sandbox flag, file name is .dlp
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag005");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box(".dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag006
 * @tc.desc: Get Sandbox flag, file name is less than ".dlp"
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag006");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("lp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag007
 * @tc.desc: Get Sandbox flag, file name has not origin suffix
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag007, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag007");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag008
 * @tc.desc: Get Sandbox flag, no keyFd
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag008, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag008");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag009
 * @tc.desc: Get Sandbox flag, keyFd type is not FD
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag009, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag009");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box("FD1"));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag010
 * @tc.desc: Get Sandbox flag, fileFd has no value key
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag010, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag009");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag011
 * @tc.desc: Get Sandbox flag, fileFd fd = -1
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag011, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag011");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(-1));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag012
 * @tc.desc: Get Sandbox flag, fileFd fd is real, but is not dlpfile fd
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpParseUnitTest, GetSandboxFlag012, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag012");
    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);

    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(plainFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

