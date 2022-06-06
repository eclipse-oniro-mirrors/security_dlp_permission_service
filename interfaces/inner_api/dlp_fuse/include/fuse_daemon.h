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
#include <map>
#include <mutex>
#include <string>

#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const int ROOT_INODE = 1;
static const int DEFAULT_ATTR_TIMEOUT = 10000;
static const int MAX_FILE_NAME_LEN = 256;
static const int ROOT_INODE_ACCESS = 0711;
static const int DEFAULT_INODE_ACCESS = 0640;
static const int FUSE_MAX_BUF_SIZE = 1024 * 1024 * 10; // 10M

enum CryptAlgo {
    AES_CTR = 1,
};

struct DlpFuseFileNode {
    fuse_ino_t inode;
    int dlpFileFd;
    std::string dlpLinkName;
    enum CryptAlgo cryptAlgo;
    unsigned char* key;
    size_t keyLen;
    bool isReadOnly;
    struct stat fileStat;
    std::atomic<int> refcount;
};

struct DlpFuseParam {
    int dlpFileFd;
    std::string dlpLinkName;
    enum CryptAlgo cryptAlgo;
    unsigned char* key;
    size_t keyLen;
    bool isReadOnly;
};

enum DaemonStatus {
    DAEMON_UNDEF,
    DAEMON_ENABLE,
    DAEMON_DISABLE,
};

class FuseDaemon {
public:
    static int InitFuseFs(int fuseDevFd);
    static struct DlpFuseFileNode *GetDlpLinkRelation(const std::string &dlpLinkName);
    static int AddDlpLinkRelation(struct DlpFuseParam *params);
    static void DelDlpLinkRelation(const std::string &dlpLinkName);
    static struct DlpFuseFileNode *GetRootFileNode();

private:
    static int WaitDaemonEnable(void);
    static void NotifyDaemonEnable(void);
    static void NotifyDaemonDisable(void);
    static void FuseFsDaemonThread(int fuseFd);
    static int FillDlpFileNode(struct DlpFuseFileNode *node, struct DlpFuseParam *params);
    static bool IsParamValid(struct DlpFuseParam *params);
    static void InitRootFileStat(void);

    static OHOS::Utils::RWLock dlpLinkLock_;
    static std::map<std::string, struct DlpFuseFileNode*> dlpLinkMap_;

    static std::condition_variable daemonEnableCv_;
    static enum DaemonStatus daemonStatus_;
    static std::mutex daemonEnableMtx_;
    static struct DlpFuseFileNode rootFuseFileNode_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif
