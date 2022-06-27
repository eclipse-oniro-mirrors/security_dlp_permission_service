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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dlp_link_file.h"
#include "dlp_link_manager.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "FuseDaemon"};
}  // namespace

std::condition_variable FuseDaemon::daemonEnableCv_;
enum DaemonStatus FuseDaemon::daemonStatus_;
std::mutex FuseDaemon::daemonEnableMtx_;
struct stat FuseDaemon::rootFileStat_;
bool FuseDaemon::init_ = false;
static const uint32_t MAX_FUSE_READ_BUFF_SIZE = 10 * 1024 * 1024; // 10M

static DlpLinkFile* GetFileNode(fuse_ino_t ino)
{
    if (ino == ROOT_INODE) {
        return nullptr;
    } else {
        return reinterpret_cast<DlpLinkFile*>(static_cast<uintptr_t>(ino));
    }
}

fuse_ino_t GetFileInode(DlpLinkFile* node)
{
    return static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(node));
}

static void FuseDaemonLookup(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    DLP_LOG_DEBUG(LABEL, "loopup file name %{public}s", name);
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
    (void)memset_s(&fep, sizeof(struct fuse_entry_param), 0, sizeof(struct fuse_entry_param));
    if (!strcmp(name, ".") || !strcmp(name, "..")) {
        fep.ino = ROOT_INODE;
        fep.attr = FuseDaemon::GetRootFileStat();
        fuse_reply_entry(req, &fep);
        return;
    }

    std::string nameStr = name;
    DlpLinkFile* node = DlpLinkManager::GetInstance().LookUpDlpLinkFile(nameStr);
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "name %{public}s can not found", name);
        fuse_reply_err(req, ENOENT);
    } else {
        DLP_LOG_DEBUG(LABEL, "name %{public}s has found", name);
        fep.ino = GetFileInode(node);
        fep.attr = node->GetLinkStat();
        fuse_reply_entry(req, &fep);
    }
}

void UpdateCurrTimeStat(struct timespec* ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

static void FuseDaemonGetattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    (void)fi;
    DLP_LOG_DEBUG(LABEL, "FuseDaemonGetattr");

    if (ino == ROOT_INODE) {
        DLP_LOG_DEBUG(LABEL, "get root inode attr\n");
        struct stat fileStat = FuseDaemon::GetRootFileStat();
        fuse_reply_attr(req, &fileStat, DEFAULT_ATTR_TIMEOUT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "get file attr is error");
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct stat fileStat = dlp->GetLinkStat();
    fuse_reply_attr(req, &fileStat, DEFAULT_ATTR_TIMEOUT);
}

// we will handle open flag later
static void FuseDaemonOpen(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    DLP_LOG_DEBUG(LABEL, "enter");
    if (ino == ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "can not open root dir");
        fuse_reply_err(req, ENOENT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "open wrong ino file");
        fuse_reply_err(req, ENOENT);
        return;
    }

    fuse_reply_open(req, fi);
    dlp->UpdateAtimeStat();
}

static DlpLinkFile* GetValidFileNode(fuse_req_t req, fuse_ino_t ino, const struct fuse_file_info* fi)
{
    (void)fi;
    if (ino == ROOT_INODE) {
        fuse_reply_err(req, ENOENT);
        return nullptr;
    }
    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlp file params error");
        fuse_reply_err(req, EBADF);
        return nullptr;
    }
    return dlp;
}

static void FuseDaemonRead(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info* fi)
{
    if (size > MAX_FUSE_READ_BUFF_SIZE) {
        DLP_LOG_ERROR(LABEL, "read size %{public}zu too large", size);
        fuse_reply_err(req, EINVAL);
        return;
    }
    DlpLinkFile* dlp = GetValidFileNode(req, ino, fi);
    if (dlp == nullptr) {
        return;
    }

    char* buf = (char*)malloc(size);
    if (buf == nullptr) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    (void)memset_s(buf, size, 0, size);

    int32_t res = dlp->Read((uint32_t)offset, buf, (uint32_t)size);
    if (res < 0) {
        fuse_reply_err(req, EIO);
    } else {
        fuse_reply_buf(req, buf, (size_t)res);
    }

    free(buf);
}

static void FuseDaemonWrite(
    fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    DLP_LOG_INFO(LABEL, "write size %{public}zu", size);
    DlpLinkFile* dlp = GetValidFileNode(req, ino, fi);
    if (dlp == nullptr) {
        return;
    }

    int32_t res = dlp->Write((uint32_t)off, (void*)buf, (uint32_t)size);
    if (res < 0) {
        fuse_reply_err(req, EIO);
    } else {
        fuse_reply_write(req, (size_t)res);
    }
}

static void FuseDaemonForgot(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    DLP_LOG_INFO(LABEL, "nlookup %{public}u", (uint32_t)nlookup);
    if (ino == ROOT_INODE) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        fuse_reply_err(req, EBADF);
        return;
    }
    if (dlp->SubAndCheckZeroRef(nlookup)) {
        delete dlp;
    }
}

static const struct fuse_lowlevel_ops g_fuseDaemonOper = {
    .lookup = FuseDaemonLookup,
    .getattr = FuseDaemonGetattr,
    .open = FuseDaemonOpen,
    .read = FuseDaemonRead,
    .write = FuseDaemonWrite,
    .forget = FuseDaemonForgot,
};

struct stat FuseDaemon::GetRootFileStat()
{
    return FuseDaemon::rootFileStat_;
}

void FuseDaemon::InitRootFileStat(void)
{
    (void)memset_s(&rootFileStat_, sizeof(rootFileStat_), 0, sizeof(rootFileStat_));
    rootFileStat_.st_ino = ROOT_INODE;
    rootFileStat_.st_mode = S_IFDIR | ROOT_INODE_ACCESS;
    rootFileStat_.st_nlink = 1;
    rootFileStat_.st_uid = getuid();
    rootFileStat_.st_gid = getgid();
    UpdateCurrTimeStat(&rootFileStat_.st_atim);
    UpdateCurrTimeStat(&rootFileStat_.st_mtim);
    UpdateCurrTimeStat(&rootFileStat_.st_ctim);
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

int FuseDaemon::WaitDaemonEnable(void)
{
    DLP_LOG_INFO(LABEL, "InitFuseFs start!");
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    if (daemonStatus_ == DAEMON_UNDEF) {
        DLP_LOG_INFO(LABEL, "InitFuseFs wait...!");
        daemonEnableCv_.wait_for(lck, std::chrono::seconds(1));
    }

    if (daemonStatus_ == DAEMON_ENABLE) {
        DLP_LOG_INFO(LABEL, "InitFuseFs ok!");
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
    int ret = snprintf_s(mountPoint, sizeof(mountPoint), MAX_FILE_NAME_LEN, "/dev/fd/%d", fuseFd);
    if (ret <= 0) {
        DLP_LOG_ERROR(LABEL, "fuseFd is error!");
        NotifyDaemonDisable();
        return;
    }

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, mountPoint);

    struct fuse_session* se = fuse_session_new(&args, &g_fuseDaemonOper, sizeof(g_fuseDaemonOper), NULL);
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

    fuse_session_destroy(se);
    fuse_opt_free_args(&args);
}

int FuseDaemon::InitFuseFs(int fuseDevFd)
{
    if (init_) {
        DLP_LOG_ERROR(LABEL, "InitFuseFs has already!");
        return -1;
    }
    init_ = true;

    if (fuseDevFd < 0) {
        DLP_LOG_ERROR(LABEL, "InitFuseFs failed: dev fd is error!");
        return -1;
    }
    daemonStatus_ = DAEMON_UNDEF;

    std::thread daemonThread(FuseFsDaemonThread, fuseDevFd);
    daemonThread.detach();
    return WaitDaemonEnable();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
