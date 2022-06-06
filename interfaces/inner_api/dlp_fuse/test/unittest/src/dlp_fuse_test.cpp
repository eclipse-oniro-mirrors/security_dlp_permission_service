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

#include "dlp_fuse_test.h"
#include "dlp_permission_log.h"
#include <thread>
#include "fuse_daemon.h"
#include <sys/mount.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <error.h>
#include <securec.h>

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFuseTest"};
}

void DlpFuseTest::SetUpTestCase()
{
}

void DlpFuseTest::TearDownTestCase()
{
}

// using for clean all link file
static const int LINK_FD_ARRY_SIZE  = 4;
static int g_linkFdArry[LINK_FD_ARRY_SIZE] = {-1};
static const std::string MOUNT_POINT_DIR = "/data/fuse/";
static const std::string FUSE_DEV = "/dev/fuse";
static const std::string FUSE_TYPE = "fuse";
static const int KERNEL_OPT_MAXLEN = 128;
static const std::string TEST_DLP_FILE = "/data/fuse_test.txt";
static const std::string TEST_LINK_FILE_NAME = "fuse_test.txt.link";
static const std::string TEST_LINK_FILE_PATH = MOUNT_POINT_DIR + "/" + TEST_LINK_FILE_NAME;

static int g_mountFd = -1;

void DlpFuseTest::PrepareDlpFuseFsMount()
{
    struct stat fstat;
    if (stat(MOUNT_POINT_DIR.c_str(), &fstat) != 0) {
        if (errno == ENOENT) {
            int ret = mkdir(MOUNT_POINT_DIR.c_str(), 0x777);
            if (ret < 0) {
                DLP_LOG_ERROR(LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "get mount point failed errno %{public}d", errno);
            return;
        }
    }

    g_mountFd = open(FUSE_DEV.c_str(), O_RDWR);
    if (g_mountFd == -1) {
        if (errno == ENODEV || errno == ENOENT) {
            DLP_LOG_ERROR(LABEL, "fuse device not found.");
        } else {
            DLP_LOG_ERROR(LABEL, "open fuse device failed.");
        }
        return;
    }

    std::string source = FUSE_DEV;
    std::string mnt = MOUNT_POINT_DIR;
    std::string type = FUSE_TYPE;

    char kernelOpts[KERNEL_OPT_MAXLEN] = "";
    (void)snprintf_s(kernelOpts, KERNEL_OPT_MAXLEN, KERNEL_OPT_MAXLEN - 1,
        "fd=%d,rootmode=40000,user_id=%u,group_id=%u",
        g_mountFd, getuid(), getgid());
    DLP_LOG_INFO(LABEL, "kernelOpts %{public}s", kernelOpts);

    int res = mount(source.c_str(), mnt.c_str(), type.c_str(), 6, kernelOpts);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "mount failed, errno %{public}d", errno);
    }
}

void DlpFuseTest::SetUp()
{
    PrepareDlpFuseFsMount();
}

void DlpFuseTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown");
    for (int i = 0; i < LINK_FD_ARRY_SIZE; i++) {
        if (g_linkFdArry[i] != -1) {
            close(g_linkFdArry[i]);
            g_linkFdArry[i] = -1;
        }
    }

    g_mountFd = -1;
    umount(MOUNT_POINT_DIR.c_str());
    rmdir(MOUNT_POINT_DIR.c_str());
    DLP_LOG_INFO(LABEL, "TearDown end");
}

/**
 * @tc.name: InitFuseFs001
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, InitFuseFs001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "InitFuseFs001");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: InitFuseFs002
 * @tc.desc: test dlp fuse init，fd is wrong and not exist
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, InitFuseFs002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "InitFuseFs002");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(0x99999);
    ASSERT_EQ(res, -1);
}

/**
 * @tc.name: AddDlpLinkRelation001
 * @tc.desc: test dlp fuse deinit
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkRelation001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkRelation001");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);

    int dlpFd = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd, 0);

    unsigned char key[5] = { 0x1 };
    struct DlpFuseParam params = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .cryptAlgo = AES_CTR,
        .isReadOnly = false,
    };

    res = FuseDaemon::AddDlpLinkRelation(&params);
    ASSERT_EQ(res, 0);

    struct DlpFuseFileNode *node = FuseDaemon::GetDlpLinkRelation(TEST_LINK_FILE_NAME);
    ASSERT_NE(node, nullptr);

    FuseDaemon::DelDlpLinkRelation(params.dlpLinkName);

    node = FuseDaemon::GetDlpLinkRelation(TEST_LINK_FILE_NAME);
    ASSERT_EQ(node, nullptr);

    unlink(TEST_DLP_FILE.c_str());
}

/**
 * @tc.name: AddDlpLinkRelation002
 * @tc.desc: test dlp fuse deinit, test param error
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkRelation002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkRelation002");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);

    unsigned char key[5] = { 0x1 };
    struct DlpFuseParam params = {
        .dlpFileFd = -1,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .cryptAlgo = AES_CTR,
        .isReadOnly = false,
    };

    res = FuseDaemon::AddDlpLinkRelation(&params);
    ASSERT_NE(res, 0);

    int dlpFd = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd, 0);

    struct DlpFuseParam params1 = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .isReadOnly = false,
    };

    res = FuseDaemon::AddDlpLinkRelation(&params1);
    ASSERT_NE(res, 0);

    struct DlpFuseParam params2 = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 0,
        .cryptAlgo = AES_CTR,
        .isReadOnly = false,
    };

    res = FuseDaemon::AddDlpLinkRelation(&params2);
    ASSERT_NE(res, 0);

    unlink(TEST_DLP_FILE.c_str());
}

/**
 * @tc.name: ReadLinkFile001
 * @tc.desc: test read link file
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, ReadLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ReadLinkFile001");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);

    int dlpFd = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd, 0);

    // fill origin file with "test"
    char writeBuf[64] = "test";
    res = write(dlpFd, writeBuf, strlen(writeBuf));
    ASSERT_GE(res, 0);
    // lseek 0x1000
    lseek(dlpFd, 0x100000, SEEK_SET);

    // write "test" again
    res = write(dlpFd, writeBuf, strlen(writeBuf));
    ASSERT_GE(res, 0);

    // clean
    lseek(dlpFd, 0, SEEK_SET);

    // add Dlp-Link relation
    unsigned char key[5] = { 0x1 };
    struct DlpFuseParam params = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .cryptAlgo = AES_CTR,
        .isReadOnly = false,
    };
    res = FuseDaemon::AddDlpLinkRelation(&params);
    ASSERT_EQ(res, 0);

    // open link file
    int linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // read link file
    char readBuf[64] = {0};
    res = read(linkfd, readBuf, 64);
    ASSERT_GE(res, 0);
    DLP_LOG_INFO(LABEL, "readBuf ret %{public}d buf %{public}s", res, readBuf);

    ASSERT_EQ(strcmp(readBuf, "test"), 0);

    // lseek
    lseek(linkfd, 0x100000, SEEK_SET);

    res = read(linkfd, readBuf, 64);
    ASSERT_GE(res, 0);
    ASSERT_EQ(strcmp(readBuf, "test"), 0);

    close(dlpFd);

    FuseDaemon::DelDlpLinkRelation(TEST_LINK_FILE_NAME);
    unlink(TEST_DLP_FILE.c_str());
}

/**
 * @tc.name: WriteLinkFile001
 * @tc.desc: test write link file
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, WriteLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "WriteLinkFile001");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);

    int dlpFd = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd, 0);

    // add Dlp-Link relation
    unsigned char key[5] = { 0x1 };
    struct DlpFuseParam params = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .cryptAlgo = AES_CTR,
        .isReadOnly = false,
    };
    res = FuseDaemon::AddDlpLinkRelation(&params);
    ASSERT_EQ(res, 0);

    // open link file
    int linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // write link file
    char writeBuf[64] = "test";
    res = write(linkfd, writeBuf, strlen(writeBuf));
    ASSERT_GE(res, 0);

    // lseek 0x1000
    lseek(linkfd, 0x1000, SEEK_SET);

    // write "test" again
    res = write(linkfd, writeBuf, strlen(writeBuf));
    ASSERT_GE(res, 0);

    // get file size
    struct stat stat1;
    res = fstat(linkfd, &stat1);
    ASSERT_EQ(res, 0);
    ASSERT_EQ(stat1.st_size, 0x1004);

    // dlpFd is used for libfuse, get another fd
    int dlpFd1 = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd1, 0);

    // open read link file
    char readBuf[64] = {0};
    res = read(dlpFd1, readBuf, 64);
    ASSERT_GE(res, 0);

    ASSERT_EQ(strcmp(readBuf, "test"), 0);

    lseek(dlpFd1, 0x1000, SEEK_SET);

    res = read(dlpFd1, readBuf, 64);
    ASSERT_GE(res, 0);
    ASSERT_EQ(strcmp(readBuf, "test"), 0);

    close(dlpFd);
    close(dlpFd1);

    FuseDaemon::DelDlpLinkRelation(TEST_LINK_FILE_NAME);
    unlink(TEST_DLP_FILE.c_str());
}

/**
 * @tc.name: WriteLinkFile002
 * @tc.desc: test write read-only link file
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, WriteLinkFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "WriteLinkFile002");
    ASSERT_GE(g_mountFd, 0);
    int res = FuseDaemon::InitFuseFs(g_mountFd);
    ASSERT_EQ(res, 0);

    int dlpFd = open(TEST_DLP_FILE.c_str(), O_RDWR | O_CREAT,  0x777);
    ASSERT_GE(dlpFd, 0);

    // add Dlp-Link relation
    unsigned char key[5] = { 0x1 };
    struct DlpFuseParam params = {
        .dlpFileFd = dlpFd,
        .dlpLinkName = TEST_LINK_FILE_NAME,
        .key = key,
        .keyLen = 5,
        .cryptAlgo = AES_CTR,
        .isReadOnly = true,
    };
    res = FuseDaemon::AddDlpLinkRelation(&params);
    ASSERT_EQ(res, 0);

    // open link file
    int linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // write link file
    char writeBuf[64] = "test";
    res = write(linkfd, writeBuf, strlen(writeBuf));
    ASSERT_EQ(res, -1);

    FuseDaemon::DelDlpLinkRelation(TEST_LINK_FILE_NAME);
    unlink(TEST_DLP_FILE.c_str());
}

