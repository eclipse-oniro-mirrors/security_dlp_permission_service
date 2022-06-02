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
#include "dlp_crypt.h"
#include "dlp_format.h"
#include "dlp_fuse.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


using namespace testing::ext;
using namespace OHOS::Security::DlpUnitTest;
using namespace DLP;
using namespace std;

uint8_t g_key[32] = { 0xdc, 0x7c, 0x8d, 0xe, 0xeb, 0x41, 0x4b, 0xb0, 0x8e, 0x24, 0x8, 0x32, 0xc7, 0x88, 0x96, 0xb6,
    0x2, 0x69, 0x65, 0x49, 0xaf, 0x3c, 0xa7, 0x8f, 0x38, 0x3d, 0xe3, 0xf1, 0x23, 0xb6, 0x22, 0xfb };
uint8_t g_iv[16] = { 0x90, 0xd5, 0xe2, 0x45, 0xaa, 0xeb, 0xa0, 0x9, 0x61, 0x45, 0xd1, 0x48, 0x4a, 0xaf, 0xc9, 0xf9 };

void DlpUnitTest::SetUpTestCase()
{
    // make test case clean
    cout << "SetUpTestCase" << endl;
}

void DlpUnitTest::TearDownTestCase()
{
    cout << "TearDownTestCase" << endl;
}

void DlpUnitTest::SetUp()
{
    cout << "SetUp" << endl;
}

void DlpUnitTest::TearDown()
{
    cout << "TearDown" << endl;
}

void DlpUnitTest::CreateDataFile() const
{
    cout << "create Data file" << endl;
}

static void dumpptr(uint8_t *ptr, uint32_t len)
{
    uint8_t *abc = nullptr;
    abc = (uint8_t *)ptr;
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
    cout << "my test!!!!!!!!!!!!" << endl;
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    int32_t ret;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .padding = DLP_PADDING_NONE,
        .algParam = &tagIv
    };
    // data == null, .size == 0;
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
        .padding = DLP_PADDING_NONE,
        .algParam = &tagIv
    };
    // data == null, .size == 0;
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
    cout << "enc hexdump:";
    dumpptr(enc, 16);
    cout << "output hexdump:";
    dumpptr(dec, 16);
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

    cout << "input hexdump:";
    dumpptr(input, 16);
    cout << "enc hexdump:";
    dumpptr(enc, 16);
    cout << "output hexdump:";
    dumpptr(dec, 16);
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

    cout << "input hexdump:";
    dumpptr(input, 16);
    cout << "enc hexdump:";
    dumpptr(enc, 16);
    cout << "output hexdump:";
    dumpptr(dec, 16);
    ret = strcmp((char *)input, (char *)dec);
    // ASSERT_EQ(0, ret);
}

/**
 * @tc.name: Dlp003
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp003, TestSize.Level1)
{
    // data == null, .size == 0;
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
    cout << "mIn.size = " << mIn.size << " mOut.size = " << mOut.size << endl;
    cout << "sha256:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    ret = DlpOpensslHash(DLP_DIGEST_SHA384, &mIn, &mOut);
    cout << "mIn.size = " << mIn.size << " mOut.size = " << mOut.size << endl;
    cout << "sha384:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    ret = DlpOpensslHash(DLP_DIGEST_SHA512, &mIn, &mOut);
    cout << "mIn.size = " << mIn.size << " mOut.size = " << mOut.size << endl;
    cout << "sha512:";
    dumpptr(out, 16);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: Dlp004
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp004, TestSize.Level1)
{
    // data == null, .size == 0;
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
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp005, TestSize.Level1)
{
    int ret = 0;
    uint8_t out[32] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 32
    };
    mIn.data = out;

    ret = DlpOpensslGenerateRandomKey(16, &mIn);
    ASSERT_EQ(-2, ret);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(out, 16);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_192, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(out, 16);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_128, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    dumpptr(out, 16);
}

/**
 * @tc.name: Dlp006
 * @tc.desc: Dlp encrypted file generate and resume.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp006, TestSize.Level1)
{
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;

    cout << "key:" << endl;
    dumpptr(key.data, 32);

    DlpFile a = DlpFile();
    struct DlpCipherParam tagIv = { .iv = {.size = 16, .data = nullptr}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .padding = DLP_PADDING_NONE,
        .algParam = &tagIv
    };

    cout << "iv:" << endl;
    dumpptr(tagIv.iv.data, 16);

    a.SetCipher(key, usage);
    struct DlpBlob cert;
    cert.data = new (nothrow)uint8_t[10];
    (void)memset(cert.data, 'a', 10);
    cert.size = 10;
    a.SetEncryptCert(cert);
    delete[] cert.data;

    string ins("abcdefhg");
    string in("/data/input.txt");
    fstream file1(in, ios::out | ios::binary);
    file1 << ins;
    file1.close();
    string out("/data/enc.txt");
    string dec("/data/dec.txt");

    a.Operation(in, out, 1);
    a.Operation(out, dec, 2);
    // remove(in.c_str());
    // remove(out.c_str());
    // remove(dec.c_str());
}

/**
 * @tc.name: Dlp006
 * @tc.desc: Dlp encrypted file generate and resume.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(DlpUnitTest, Dlp007, TestSize.Level1)
{
    struct DlpBlob key = { 32, nullptr };
    struct DlpBlob iv = { 16, nullptr };

    key.data = g_key;
    iv.data = g_iv;

    int fd = open("/data/enc.txt", O_RDWR);
    printf("fd %d, errno %d\n", fd, errno);
    int ret = 0;

    ret = DlpFileAdd(fd, &key, &iv);
    char buf[32] = {0};
    ret = DlpFileRead(fd, 0, (void *)buf, 16);
    printf("1reading buff %s\n", buf);

    ret = DlpFileWrite(fd, 0, (void *)"ooooooooooo", sizeof("ooooooooooo"));

    ret = DlpFileRead(fd, 0, (void *)buf, 16);
    printf("2reading buff %s\n", buf);
    ret = DlpFileDel(fd);
    close(fd);
}
