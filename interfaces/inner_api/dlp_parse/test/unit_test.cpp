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
#include "dlp_crypt.h"
#include "dlp_file_kits.h"
#include "dlp_permission.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpUnitTest;
using namespace OHOS::Security::DlpPermission;
using namespace std;

uint8_t g_key[32] = { 0xdc, 0x7c, 0x8d, 0xe, 0xeb, 0x41, 0x4b, 0xb0, 0x8e, 0x24, 0x8, 0x32, 0xc7, 0x88, 0x96, 0xb6,
    0x2, 0x69, 0x65, 0x49, 0xaf, 0x3c, 0xa7, 0x8f, 0x38, 0x3d, 0xe3, 0xf1, 0x23, 0xb6, 0x22, 0xfb };
uint8_t g_iv[16] = { 0x90, 0xd5, 0xe2, 0x45, 0xaa, 0xeb, 0xa0, 0x9, 0x61, 0x45, 0xd1, 0x48, 0x4a, 0xaf, 0xc9, 0xf9 };

void DlpUnitTest::SetUpTestCase() {}

void DlpUnitTest::TearDownTestCase() {}

void DlpUnitTest::SetUp() {}

void DlpUnitTest::TearDown() {}

void DlpUnitTest::CreateDataFile() const
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
 * @tc.name: Dlp001
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp001, TestSize.Level1)
{
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
    ret = strcmp((char *)input, (char *)dec);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: Dlp002
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp002, TestSize.Level1)
{
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
    ret = strcmp((char *)input, (char *)dec);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: Dlp003
 * @tc.desc: HASH test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp003, TestSize.Level1)
{
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
 * @tc.name: Dlp004
 * @tc.desc: split hash test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp004, TestSize.Level1)
{
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
 * @tc.name: Dlp005
 * @tc.desc: random generate test
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp005, TestSize.Level1)
{
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
 * @tc.name: Dlp006
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
#define ENC_BUF_LEN (10 * 1024 * 1024)
HWTEST_F(DlpUnitTest, Dlp006, TestSize.Level1)
{
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
 * @tc.name: Dlp0007
 * @tc.desc: Dlp encrypt && decrypt test with invalid args.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp0007, TestSize.Level1)
{
    int32_t ret;

    ret = DlpOpensslAesEncrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    ret = DlpOpensslAesDecrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: GetSanboxFlag001
 * @tc.desc: Get Sandbox flag
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpUnitTest, GetSandboxFlag001, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    bool res = DlpFileKits::GetSandboxFlag(want);
    ASSERT_FALSE(res);

    want.SetParam(TAG_DLP_TEST_PARAM, 10);
    res = DlpFileKits::GetSandboxFlag(want);
    ASSERT_TRUE(res);

    want.SetParam(TAG_DLP_TEST_PARAM, 0);
    res = DlpFileKits::GetSandboxFlag(want);
    ASSERT_FALSE(res);
}
