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

#ifndef FUSE_FS_DAEMON_H
#define FUSE_FS_DAEMON_H

#include <condition_variable>
#include <fuse_lowlevel.h>
#include <mutex>
#include <string>
#include "dlp_link_file.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const int ROOT_INODE = 1;
static const int DEFAULT_ATTR_TIMEOUT = 10000;
static const int MAX_FILE_NAME_LEN = 256;
static const int ROOT_INODE_ACCESS = 0711;
static const int DEFAULT_INODE_ACCESS = 0640;
static const size_t FUSE_MAX_BUF_SIZE = 1024 * 1024 * 10;  // 10M
static const unsigned int MAX_INT_NUMBER = 0x7fffffff;
static const unsigned int MAX_KEY_LEN = 0x10000;  // 64K
static const std::string DEFAULT_DLP_LINK_FILE = "default.dlp";
static const std::string DEFAULT_DLP_LINK_FILE_PATH = "/data/fuse/"+ DEFAULT_DLP_LINK_FILE;

enum CryptAlgo {
    AES_CTR = 1,
};

enum DaemonStatus {
    DAEMON_UNDEF,
    DAEMON_ENABLE,
    DAEMON_DISABLE,
};

fuse_ino_t GetFileInode(struct DlpFuseFileNode* node);
void UpdateCurrTimeStat(struct timespec* ts);
fuse_ino_t GetFileInode(DlpLinkFile* node);

class FuseDaemon {
public:
    static int InitFuseFs(int fuseDevFd);
    static struct stat GetRootFileStat();
    static int WaitDaemonEnable(void);
    static void NotifyDaemonEnable(void);
    static void NotifyDaemonDisable(void);
    static void NotifyKernelNoFlush(void);
    static void InitRootFileStat(void);
    static void FuseFsDaemonThread(int fuseFd);

    static std::condition_variable daemonEnableCv_;
    static enum DaemonStatus daemonStatus_;
    static std::mutex daemonEnableMtx_;
    static struct stat rootFileStat_;
    static bool init_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif
