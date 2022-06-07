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

#include "fuse_daemon.h"

#include <securec.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unistd.h>

#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "FuseDaemon"};
} // namespace

OHOS::Utils::RWLock FuseDaemon::dlpLinkLock_;
std::map<std::string, struct DlpFuseFileNode*> FuseDaemon::dlpLinkMap_;
std::condition_variable FuseDaemon::daemonEnableCv_;
enum DaemonStatus FuseDaemon::daemonStatus_ = DAEMON_UNDEF;
std::mutex FuseDaemon::daemonEnableMtx_;
struct DlpFuseFileNode FuseDaemon::rootFuseFileNode_;

static struct DlpFuseFileNode *GetFileNode(fuse_ino_t ino)
{
    if (ino == ROOT_INODE) {
        return FuseDaemon::GetRootFileNode();
    } else {
        return reinterpret_cast<struct DlpFuseFileNode *>(static_cast<uintptr_t>(ino));
    }
}

static fuse_ino_t GetFileInode(struct DlpFuseFileNode *node)
{
    return static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(node));
}

static void FuseDaemonLookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    if (name == nullptr) {
        DLP_LOG_ERROR(LABEL, "name is null");
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (parent != ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "parent is not root inode, can not look up");
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct fuse_entry_param fep;
    memset_s(&fep, sizeof(struct fuse_entry_param), 0, sizeof(struct fuse_entry_param));
    if (!strcmp(name, ".") || !strcmp(name, "..")) {
        fep.ino = ROOT_INODE;
        fep.attr = FuseDaemon::GetRootFileNode()->fileStat;
        fuse_reply_entry(req, &fep);
        return;
    }

    std::string nameStr = name;
    struct DlpFuseFileNode* node = FuseDaemon::GetDlpLinkRelation(nameStr);
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "name %{public}s can not found", name);
        fuse_reply_err(req, ENOENT);
    } else {
        DLP_LOG_INFO(LABEL, "name %{public}s has found, node->inode %{public}lu", name, node->inode);
        node->refcount++;
        fep.ino = node->inode;
        fep.attr = node->fileStat;
        fuse_reply_entry(req, &fep);
    }
}

static void UpdateCurrTimeStat(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

static void UpdateDlpFileSize(struct DlpFuseFileNode *dlp)
{
    struct stat fileStat;
    int ret = fstat(dlp->dlpFileFd, &fileStat);
    if (ret < 0) {
        DLP_LOG_ERROR(LABEL, "get file %{public}s stat failed", dlp->dlpLinkName.c_str());
        return;
    }
    dlp->fileStat.st_size = fileStat.st_size;
}

static void FuseDaemonGetattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    (void) fi;

    if (ino == ROOT_INODE) {
        DLP_LOG_DEBUG(LABEL, "get root inode attr\n");
        fuse_reply_attr(req, &(FuseDaemon::GetRootFileNode()->fileStat), DEFAULT_ATTR_TIMEOUT);
        return;
    }

    struct DlpFuseFileNode *dlp = GetFileNode(ino);
    if (dlp == nullptr || dlp->dlpFileFd <= 0) {
        DLP_LOG_ERROR(LABEL, "get file attr is error");
        fuse_reply_err(req, ENOENT);
        return;
    }

    UpdateDlpFileSize(dlp);
    DLP_LOG_INFO(LABEL, "name %{public}s size %{public}ld", dlp->dlpLinkName.c_str(), dlp->fileStat.st_size);
    fuse_reply_attr(req, &dlp->fileStat, DEFAULT_ATTR_TIMEOUT);
}

// we will handle open flag later
static void FuseDaemonOpen(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    DLP_LOG_DEBUG(LABEL, "enter");
    if (ino == ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "can not open root dir");
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct DlpFuseFileNode *dlp = GetFileNode(ino);
    if (dlp == nullptr || dlp->dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "open wrong ino file");
        fuse_reply_err(req, ENOENT);
    } else {
        fi->fh = dlp->dlpFileFd;
        fuse_reply_open(req, fi);
    }
    UpdateCurrTimeStat(&dlp->fileStat.st_atim);
}

static struct DlpFuseFileNode *GetValidFileNode(fuse_req_t req, fuse_ino_t ino, const struct fuse_file_info *fi)
{
    if (ino == ROOT_INODE) {
        fuse_reply_err(req, ENOENT);
        return nullptr;
    }
    struct DlpFuseFileNode *dlp = GetFileNode(ino);
    if (dlp == nullptr || dlp->dlpFileFd <= 0 ||
        fi == nullptr || fi->fh <= 0) {
        DLP_LOG_ERROR(LABEL, "dlp file params error");
        fuse_reply_err(req, EBADF);
        return nullptr;
    }
    return dlp;
}

static void FuseDaemonRead(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    DLP_LOG_INFO(LABEL, "ino %{public}lu size %{public}zu off %{public}ld", ino, size, offset);
    struct DlpFuseFileNode *dlp = GetValidFileNode(req, ino, fi);
    if (dlp == nullptr) {
        return;
    }

    int fd = fi->fh;
    lseek(fd, offset, SEEK_SET);
    if (size > FUSE_MAX_BUF_SIZE) {
        DLP_LOG_ERROR(LABEL, "read buf too large");
        fuse_reply_err(req, EINVAL);
        return;
    }

    char *buf = (char *)malloc(size);
    if (!buf) {
        DLP_LOG_ERROR(LABEL, "read buf malloc failed size %{public}zu", size);
        fuse_reply_err(req, EINVAL);
        return;
    }
    (void)memset_s(buf, size, 0, size);

    int readLen = read(fd, buf, size);
    if (readLen < 0) {
        DLP_LOG_ERROR(LABEL, "readLen < 0, errno %{public}d", errno);
        fuse_reply_err(req, EINVAL);
        free(buf);
        return;
    }

    DLP_LOG_INFO(LABEL, "readLen %{public}d", readLen);
    fuse_reply_buf(req, buf, readLen);
    UpdateCurrTimeStat(&dlp->fileStat.st_atim);
    free(buf);
}

static void FuseDaemonWrite(fuse_req_t req, fuse_ino_t ino, const char *buf,
    size_t size, off_t off, struct fuse_file_info *fi)
{
    DLP_LOG_INFO(LABEL, "ino %{public}lu size %{public}zu off %{public}ld", ino, size, off);
    struct DlpFuseFileNode *dlp = GetValidFileNode(req, ino, fi);
    if (dlp == nullptr) {
        return;
    }
    if (dlp->isReadOnly) {
        DLP_LOG_ERROR(LABEL, "file is read only");
        fuse_reply_err(req, EPERM);
        return;
    }

    int fd = fi->fh;
    lseek(fd, off, SEEK_SET);
    size_t writeLen = write(fd, buf, size);
    if (writeLen < 0) {
        DLP_LOG_ERROR(LABEL, "write len < 0, errno %{public}d", errno);
        fuse_reply_err(req, EIO);
        return;
    }
    DLP_LOG_INFO(LABEL, "write len %{public}zu", writeLen);

    fuse_reply_write(req, writeLen);
    UpdateCurrTimeStat(&dlp->fileStat.st_mtim);
    fsync(fd);
}

static void FuseDaemonForgot(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    if (ino == ROOT_INODE) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct DlpFuseFileNode *dlp = GetFileNode(ino);
    if (dlp == nullptr || dlp->dlpFileFd <= 0) {
        fuse_reply_err(req, EBADF);
        return;
    }
    dlp->refcount -= nlookup;
    if (dlp->refcount <= 0) {
        free(dlp);
    }
}

static const struct fuse_lowlevel_ops g_fuseDaemonOper = {
    .lookup     = FuseDaemonLookup,
    .getattr    = FuseDaemonGetattr,
    .open       = FuseDaemonOpen,
    .read       = FuseDaemonRead,
    .write      = FuseDaemonWrite,
    .forget     = FuseDaemonForgot,
};

struct DlpFuseFileNode *FuseDaemon::GetRootFileNode()
{
    return &FuseDaemon::rootFuseFileNode_;
}

void FuseDaemon::InitRootFileStat(void)
{
    struct stat *fstat = &rootFuseFileNode_.fileStat;
    (void)memset_s(fstat, sizeof(*fstat), 0, sizeof(*fstat));
    fstat->st_ino = ROOT_INODE;
    fstat->st_mode = S_IFDIR | ROOT_INODE_ACCESS;
    fstat->st_nlink = 1;
    fstat->st_uid = getuid();
    fstat->st_gid = getgid();
    UpdateCurrTimeStat(&fstat->st_atim);
    UpdateCurrTimeStat(&fstat->st_mtim);
    UpdateCurrTimeStat(&fstat->st_ctim);

    rootFuseFileNode_.inode = ROOT_INODE;
}

void FuseDaemon::NotifyDaemonEnable(void)
{
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    daemonStatus_ = DAEMON_ENABLE;
    daemonEnableCv_.notify_all();
}

void FuseDaemon::NotifyDaemonDisable(void)
{
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    daemonStatus_ = DAEMON_DISABLE;
    daemonEnableCv_.notify_all();
}

int FuseDaemon::FillDlpFileNode(struct DlpFuseFileNode *node, struct DlpFuseParam *params)
{
    if (node == nullptr || params == nullptr) {
        DLP_LOG_ERROR(LABEL, "params is error.");
        return -1;
    }

    node->inode = GetFileInode(node);
    node->dlpFileFd = params->dlpFileFd;
    node->dlpLinkName = params->dlpLinkName;
    node->cryptAlgo = params->cryptAlgo;

    node->key = (unsigned char *)malloc(params->keyLen);
    if (node->key == NULL) {
        DLP_LOG_ERROR(LABEL, "malloc key is error");
        return -1;
    }
    int ret = memcpy_s(node->key, sizeof(node->key), params->key, sizeof(params->key));
    if (ret) {
        DLP_LOG_ERROR(LABEL, "memcpy key is error");
        return -1;
    }
    node->keyLen = params->keyLen;
    node->fileStat.st_ino = node->inode;
    node->fileStat.st_mode = S_IFREG | DEFAULT_INODE_ACCESS;
    node->fileStat.st_nlink = 1;
    node->fileStat.st_uid = getuid();
    node->fileStat.st_gid = getgid();
    node->isReadOnly = params->isReadOnly;

    UpdateDlpFileSize(node);
    UpdateCurrTimeStat(&node->fileStat.st_atim);
    UpdateCurrTimeStat(&node->fileStat.st_mtim);
    UpdateCurrTimeStat(&node->fileStat.st_ctim);
    return 0;
}

bool FuseDaemon::IsParamValid(struct DlpFuseParam *params)
{
    return (params != nullptr && params->dlpFileFd >= 0
        && params->key != nullptr && params->keyLen != 0
        && params->cryptAlgo == AES_CTR);
}

int FuseDaemon::AddDlpLinkRelation(struct DlpFuseParam *params)
{
    if (GetDlpLinkRelation(params->dlpLinkName) != nullptr) {
        DLP_LOG_WARN(LABEL, "dlpLinkName %{public}s exist.", params->dlpLinkName.c_str());
        return 0;
    }

    struct stat fileStat;
    if (fstat(params->dlpFileFd, &fileStat) < 0) {
        DLP_LOG_ERROR(LABEL, "%{public}d is wrong fd.", params->dlpFileFd);
        return -1;
    }

    if (!IsParamValid(params)) {
        DLP_LOG_ERROR(LABEL, "dlp params error!");
        return -1;
    }

    struct DlpFuseFileNode *node = (struct DlpFuseFileNode *)malloc(sizeof(struct DlpFuseFileNode));
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc dlp file node failed!");
        return -1;
    }

    (void)memset_s(node, sizeof(struct DlpFuseFileNode), 0, sizeof(struct DlpFuseFileNode));

    if (FillDlpFileNode(node, params)) {
        DLP_LOG_ERROR(LABEL, "fill dlp file node failed!");
        return -1;
    }

    {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkLock_);
        std::string fileName = params->dlpLinkName;
        DLP_LOG_INFO(LABEL, "AddDlpLinkRelation: filename %{public}s\n", fileName.c_str());
        dlpLinkMap_[fileName] = node;
    }
    return 0;
}

void FuseDaemon::DelDlpLinkRelation(const std::string &dlpLinkName)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkLock_);
    if (dlpLinkMap_.count(dlpLinkName) > 0) {
        struct DlpFuseFileNode* node = dlpLinkMap_[dlpLinkName];
        dlpLinkMap_.erase(dlpLinkName);
        if (node != nullptr && node->refcount <= 0) {
            if (node->key != nullptr) {
                free(node->key);
            }
            free(node);
        }
    }
}

struct DlpFuseFileNode* FuseDaemon::GetDlpLinkRelation(const std::string &dlpLinkName)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(dlpLinkLock_);
    if (dlpLinkMap_.count(dlpLinkName) > 0) {
        struct DlpFuseFileNode* node = dlpLinkMap_[dlpLinkName];
        return node;
    }
    return nullptr;
}

int FuseDaemon::WaitDaemonEnable(void)
{
    DLP_LOG_INFO(LABEL, "InitFuseFs start!");
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    if (daemonStatus_ == DAEMON_UNDEF) {
        DLP_LOG_INFO(LABEL, "InitFuseFs wait...!");
        daemonEnableCv_.wait_for(lck, std::chrono::seconds(1));
    }

    if (daemonStatus_ == DAEMON_ENABLE) {
        DLP_LOG_INFO(LABEL, "InitFuseFs ok!");\
        return 0;
    }

    DLP_LOG_INFO(LABEL, "InitFuseFs failed!");
    return -1;
}

void FuseDaemon::FuseFsDaemonThread(int fuseFd)
{
    struct stat fileStat;
    if (fstat(fuseFd, &fileStat) < 0) {
        DLP_LOG_ERROR(LABEL, "%{public}d is wrong fd.", fuseFd);
        NotifyDaemonDisable();
        return;
    }

    char mountPoint[MAX_FILE_NAME_LEN] = {0};
    int ret = snprintf_s(mountPoint, sizeof(mountPoint), MAX_FILE_NAME_LEN, "/dev/fd/%u", fuseFd);
    if (ret <= 0) {
        DLP_LOG_ERROR(LABEL, "fuseFd is error!");
        NotifyDaemonDisable();
        return;
    }

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, mountPoint);

    struct fuse_session *se = fuse_session_new(&args, &g_fuseDaemonOper, sizeof(g_fuseDaemonOper), NULL);
    if (se == NULL) {
        DLP_LOG_ERROR(LABEL, "create fuse session failed!");
        NotifyDaemonDisable();
        fuse_opt_free_args(&args);
        return;
    }

    if (fuse_session_mount(se, mountPoint) != 0) {
        DLP_LOG_ERROR(LABEL, "create fuse session failed!");
        NotifyDaemonDisable();
        fuse_session_destroy(se);
        fuse_opt_free_args(&args);
        return;
    }

    InitRootFileStat();
    NotifyDaemonEnable();

    ret = fuse_session_loop(se);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "fuse_session_loop end!");
    }
    daemonStatus_ = DAEMON_UNDEF;
    fuse_session_destroy(se);
    fuse_opt_free_args(&args);
}

int FuseDaemon::InitFuseFs(int fuseDevFd)
{
    if (fuseDevFd < 0) {
        DLP_LOG_ERROR(LABEL, "InitFuseFs failed: dev fd is error!");
        return -1;
    }
    daemonStatus_ = DAEMON_UNDEF;
    std::thread daemonThread(FuseFsDaemonThread, fuseDevFd);
    daemonThread.detach();

    return WaitDaemonEnable();
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

