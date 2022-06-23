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
static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const int TEST_USER_COUNT = 2;
static const int RAND_STR_SIZE = 16;
static const int EXPIRT_TIME = 10000;

void DlpFuseTest::SetUpTestCase()
{
}

void DlpFuseTest::TearDownTestCase()
{
}

void DlpFuseTest::SetUp()
{
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

    dup2(g_mountFd, FUSE_DEV_FD);

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

/**
 * @tc.name: GenerateDlpFile001
 * @tc.desc: test dlp file generate, owner is current
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, GenerateDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile001");

    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    // owner is current account
    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop);
    ASSERT_NE(dlpfile, nullptr);
    int recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(dlpFileFd, 0);

    int result = DlpFileManager::GetInstance().RecoverDlpFile(dlpfile, recoveryFileFd);
    ASSERT_EQ(result, 0);

    lseek(recoveryFileFd, 0, SEEK_SET);
    char buffer2[16] = {0};
    result = read(recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);
}

/**
 * @tc.name: GenerateDlpFile002
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, GenerateDlpFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile002");

    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop);
    ASSERT_NE(dlpfile, nullptr);
    int recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(dlpFileFd, 0);

    int result = DlpFileManager::GetInstance().RecoverDlpFile(dlpfile, recoveryFileFd);
    ASSERT_EQ(result, 0);

    lseek(recoveryFileFd, 0, SEEK_SET);
    char buffer2[16] = {0};
    result = read(recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);
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

    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop);
    ASSERT_NE(dlpfile, nullptr);
    int result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);

    dlpfile = DlpFileManager::GetInstance().OpenDlpFile(dlpFileFd);
    ASSERT_NE(dlpfile, nullptr);

    int recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(dlpFileFd, 0);

    PermissionPolicy policy;
    dlpfile->GetPolicy(policy);
    ASSERT_EQ(policy.ownerAccount_, prop.ownerAccount);

    std::vector<AuthUserInfo>& authUsers = policy.authUsers_;
    ASSERT_EQ(authUsers.size(), prop.authUsers.size());

    for (int i = 0; i < authUsers.size(); i++) {
        ASSERT_EQ(authUsers[i].authAccount, prop.authUsers[i].authAccount);
        ASSERT_EQ(authUsers[i].authPerm, prop.authUsers[i].authPerm);
        ASSERT_EQ(authUsers[i].permExpiryTime, prop.authUsers[i].permExpiryTime);
        ASSERT_EQ(authUsers[i].authAccountType, prop.authUsers[i].authAccountType);
    }

    std::string contactAccount;
    dlpfile->GetContactAccount(contactAccount);
    ASSERT_EQ(contactAccount, prop.contractAccount);

    result = DlpFileManager::GetInstance().RecoverDlpFile(dlpfile, recoveryFileFd);
    ASSERT_EQ(result, 0);

    lseek(recoveryFileFd, 0, SEEK_SET);

    char buffer2[16] = {0};
    result = read(recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);
}

/**
 * @tc.name: InitFuseFs001
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile001, TestSize.Level1)
{
    PrepareDlpFuseFsMount();

    DLP_LOG_INFO(LABEL, "AddDlpLinkFile001");
    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop);
    ASSERT_NE(dlpfile, nullptr);

    int result = DlpLinkManager::GetInstance().AddDlpLinkFile(dlpfile, TEST_LINK_FILE_NAME);
    ASSERT_EQ(result, 0);

    DlpLinkFile* link = DlpLinkManager::GetInstance().LookUpDlpLinkFile(TEST_LINK_FILE_NAME);
    ASSERT_NE(dlpfile, nullptr);
    link->SubAndCheckZeroRef(1);

    // open link file
    int linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // read link file
    char readBuf[64] = {0};
    result = read(linkfd, readBuf, 64);
    DLP_LOG_INFO(LABEL, "readBuf ret %{public}d errno %{public}d", result, errno);
    ASSERT_GE(result, 0);
    DLP_LOG_INFO(LABEL, "readBuf ret %{public}d buf %{public}s", result, readBuf);

    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    result = DlpLinkManager::GetInstance().DeleteDlpLinkFile(dlpfile);
    ASSERT_EQ(result, 0);

    result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);
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

    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    int dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);
    ASSERT_GE(dlpFileFd, 0);

    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    std::shared_ptr<DlpFile> dlpfile = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd, dlpFileFd, prop);
    ASSERT_NE(dlpfile, nullptr);
    int result = DlpFileManager::GetInstance().CloseDlpFile(dlpfile);
    ASSERT_EQ(result, 0);

    bool isDlpFile = DlpFileManager::GetInstance().IsDlpFile(dlpFileFd);
    ASSERT_TRUE(isDlpFile);

    isDlpFile = DlpFileManager::GetInstance().IsDlpFile(plainFileFd);
    ASSERT_FALSE(isDlpFile);

    isDlpFile = DlpFileManager::GetInstance().IsDlpFile(100000);
    ASSERT_FALSE(isDlpFile);
}

