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

#include <cstring>
#include <error.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include "dlp_file.h"
#include "dlp_file_manager.h"
#include "dlp_link_file.h"
#include "dlp_link_manager.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFuseTest"};
// using for clean all link file
static const int32_t LINK_FD_ARRY_SIZE = 4;
static int32_t g_linkFdArry[LINK_FD_ARRY_SIZE] = {-1};
static const std::string MOUNT_POINT_DIR = "/data/fuse/";
static const std::string FUSE_DEV = "/dev/fuse";
static const std::string FUSE_TYPE = "fuse";
static const int32_t KERNEL_OPT_MAXLEN = 128;
static const std::string TEST_LINK_FILE_NAME = "fuse_test.txt.link";
static const std::string TEST_LINK_FILE_PATH = MOUNT_POINT_DIR + "/" + TEST_LINK_FILE_NAME;
static int32_t g_mountFd = -1;
static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const int32_t TEST_USER_COUNT = 2;
static const int32_t RAND_STR_SIZE = 16;
static const int32_t EXPIRT_TIME = 10000;
static int g_plainFileFd = -1;
static int g_dlpFileFd = -1;
static int g_recoveryFileFd = -1;
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
}

void DlpFuseTest::SetUpTestCase()
{}

void DlpFuseTest::TearDownTestCase()
{
    g_mountFd = -1;
    int ret = umount(MOUNT_POINT_DIR.c_str());
    DLP_LOG_INFO(LABEL, "umount ret %{public}d", ret);
    rmdir(MOUNT_POINT_DIR.c_str());
}

void DlpFuseTest::SetUp()
{}

void DlpFuseTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown");
    for (int32_t i = 0; i < LINK_FD_ARRY_SIZE; i++) {
        if (g_linkFdArry[i] != -1) {
            close(g_linkFdArry[i]);
            g_linkFdArry[i] = -1;
        }
    }
    if (g_plainFileFd != -1) {
        close(g_plainFileFd);
        g_plainFileFd = -1;
    }
    if (g_dlpFileFd != -1) {
        close(g_dlpFileFd);
        g_dlpFileFd = -1;
    }
    if (g_recoveryFileFd != -1) {
        close(g_recoveryFileFd);
        g_recoveryFileFd = -1;
    }

    if (g_Dlpfile != nullptr) {
        DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
        g_Dlpfile = nullptr;
    }
    DLP_LOG_INFO(LABEL, "TearDown end");
}

namespace {
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

static void GenerateRandProperty(struct DlpProperty& encProp)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto seed = std::time(nullptr);
    std::srand(seed);
    encProp.ownerAccount = DEFAULT_CURRENT_ACCOUNT;
    encProp.ownerAccountType = CLOUD_ACCOUNT;
    for (uint32_t user = 0; user < TEST_USER_COUNT; ++user) {
        AuthUserInfo perminfo = {.authAccount = GenerateRandStr(RAND_STR_SIZE),
            .authPerm = (AuthPermType)READ_ONLY,
            .permExpiryTime = curTime + EXPIRT_TIME,
            .authAccountType = (AccountType)CLOUD_ACCOUNT};
        encProp.authUsers.emplace_back(perminfo);
    }
    encProp.contractAccount = GenerateRandStr(TEST_USER_COUNT);
}

void PrepareDlpFuseFsMount()
{
    struct stat fstat;
    if (stat(MOUNT_POINT_DIR.c_str(), &fstat) != 0) {
        if (errno == ENOENT) {
            int32_t ret = mkdir(MOUNT_POINT_DIR.c_str(), 0x777);
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

    dup2(g_mountFd, FUSE_DEV_FD);

    std::string source = FUSE_DEV;
    std::string mnt = MOUNT_POINT_DIR;
    std::string type = FUSE_TYPE;

    char kernelOpts[KERNEL_OPT_MAXLEN] = "";
    (void)snprintf_s(kernelOpts, KERNEL_OPT_MAXLEN, KERNEL_OPT_MAXLEN - 1,
        "fd=%d,rootmode=40000,user_id=%u,group_id=%u", g_mountFd, getuid(), getgid());
    DLP_LOG_INFO(LABEL, "kernelOpts %{public}s", kernelOpts);

    int32_t res = mount(source.c_str(), mnt.c_str(), type.c_str(), 6, kernelOpts);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "mount failed, errno %{public}d", errno);
    }
}
}
/**
 * @tc.name: GenerateDlpFile001
 * @tc.desc: test dlp file generate, owner is current
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, GenerateDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile001");

    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_recoveryFileFd, 0);

    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);

    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    char buffer2[16] = {0};
    result = read(g_recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, 6);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: OpenDlpFile001
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, OpenDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OpenDlpFile001");

    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;

    result = DlpFileManager::GetInstance().OpenDlpFile(g_dlpFileFd, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    PermissionPolicy policy;
    g_Dlpfile->GetPolicy(policy);
    ASSERT_EQ(policy.ownerAccount_, prop.ownerAccount);

    std::vector<AuthUserInfo>& authUsers = policy.authUsers_;
    ASSERT_EQ(authUsers.size(), prop.authUsers.size());

    for (int32_t i = 0; i < (int32_t)authUsers.size(); i++) {
        ASSERT_EQ(authUsers[i].authAccount, prop.authUsers[i].authAccount);
        ASSERT_EQ(authUsers[i].authPerm, prop.authUsers[i].authPerm);
        ASSERT_EQ(authUsers[i].permExpiryTime, prop.authUsers[i].permExpiryTime);
        ASSERT_EQ(authUsers[i].authAccountType, prop.authUsers[i].authAccountType);
    }

    std::string contactAccount;
    g_Dlpfile->GetContactAccount(contactAccount);
    ASSERT_EQ(contactAccount, prop.contractAccount);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_recoveryFileFd, 0);
    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);

    lseek(g_recoveryFileFd, 0, SEEK_SET);

    char buffer2[16] = {0};
    result = read(g_recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: testIsDlpFile
 * @tc.desc: test check dlp file
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, testIsDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "testIsDlpFile001");

    int32_t plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int32_t dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = nullptr;
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop, dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(dlpfile, nullptr);
    result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);

    bool isDlpFile = false;
    result = DlpFileManager::GetInstance().IsDlpFile(dlpFileFd, isDlpFile);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(isDlpFile);

    result = DlpFileManager::GetInstance().IsDlpFile(plainFileFd, isDlpFile);
    ASSERT_NE(result, 0);
    ASSERT_FALSE(isDlpFile);

    result = DlpFileManager::GetInstance().IsDlpFile(100000, isDlpFile);
    ASSERT_NE(result, 0);
    ASSERT_FALSE(isDlpFile);
}

/**
 * @tc.name: AddDlpLinkFile001
 * @tc.desc: test dlp link file read
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile001");
    PrepareDlpFuseFsMount();
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    write(g_plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    DlpLinkFile* link = DlpLinkManager::GetInstance().LookUpDlpLinkFile(TEST_LINK_FILE_NAME);
    ASSERT_NE(g_Dlpfile, nullptr);
    link->SubAndCheckZeroRef(1);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // read link file
    char readBuf[64] = {0};
    result = read(linkfd, readBuf, 64);
    ASSERT_GE(result, 0);

    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile);
    ASSERT_EQ(result, 0);

    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile002
 * @tc.desc: test dlp link file read twice
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile002");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    ASSERT_NE(lseek(g_plainFileFd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    char readBuf[7] = {0};
    result = read(linkfd, readBuf, 6);
    ASSERT_GE(result, 0);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    lseek(linkfd, 0x100000, SEEK_SET);
    result = read(linkfd, readBuf, 6);
    ASSERT_EQ(result, 6);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile003
 * @tc.desc: test dlp fuse write alignd
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile003");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);
    ASSERT_NE(lseek(g_plainFileFd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    DlpLinkFile* link = DlpLinkManager::GetInstance().LookUpDlpLinkFile(TEST_LINK_FILE_NAME);
    ASSERT_NE(g_Dlpfile, nullptr);
    link->SubAndCheckZeroRef(1);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    ASSERT_NE(lseek(linkfd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    close(linkfd);

    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile);
    ASSERT_EQ(result, 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_dlpFileFd, 0);
    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);

    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    char readBuf[7] = {0};
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_GE(result, 0);
    ASSERT_EQ(strcmp(readBuf, "111111"), 0);

    ASSERT_NE(lseek(g_recoveryFileFd, 0x100000, SEEK_SET), -1);
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_EQ(result, 6);
    ASSERT_EQ(strcmp(readBuf, "111111"), 0);
}

/**
 * @tc.name: AddDlpLinkFile004
 * @tc.desc: test dlp fuse write not alignd
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile004");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);
    ASSERT_NE(lseek(g_plainFileFd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    ASSERT_NE(lseek(linkfd, 6, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    ASSERT_NE(lseek(linkfd, 0x100006, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    close(linkfd);

    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile);
    ASSERT_EQ(result, 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_dlpFileFd, 0);
    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);

    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);

    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    char readBuf[7] = {0};
    lseek(g_recoveryFileFd, 6, SEEK_SET);
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_GE(result, 0);
    ASSERT_EQ(strcmp(readBuf, "111111"), 0);
    ASSERT_NE(lseek(g_recoveryFileFd, 0x100006, SEEK_SET), -1);

    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_EQ(result, 6);
    ASSERT_EQ(strcmp(readBuf, "111111"), 0);
}

/**
 * @tc.name: AddDlpLinkFile005
 * @tc.desc: test dlp fuse hole part
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile005");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd, g_dlpFileFd, prop, g_Dlpfile);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    result = DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    ASSERT_NE(lseek(linkfd, 6, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    ASSERT_NE(lseek(linkfd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "111111", strlen("111111")), -1);
    close(linkfd);

    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile);
    ASSERT_EQ(result, 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(g_dlpFileFd, 0);
    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);

    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);

    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    char readBuf[7] = {0};
    ASSERT_NE(lseek(g_recoveryFileFd, 6, SEEK_SET), -1);
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_GE(result, 0);

    ASSERT_EQ(strcmp(readBuf, "111111"), 0);
    ASSERT_NE(lseek(g_recoveryFileFd, 0x100000, SEEK_SET), -1);
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_EQ(result, 6);
    ASSERT_NE(lseek(g_recoveryFileFd, 0x1000, SEEK_SET), -1);
    result = read(g_recoveryFileFd, readBuf, 6);
    ASSERT_EQ(result, 6);

    char emptyBuf[6] = {0};
    ASSERT_EQ(memcmp(readBuf, emptyBuf, 6), 0);
}
