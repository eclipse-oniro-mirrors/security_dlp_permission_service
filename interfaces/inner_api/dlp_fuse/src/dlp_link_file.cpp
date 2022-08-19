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

#include "dlp_link_file.h"

#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpLinkFile"};
static const int DEFAULT_INODE_ACCESS = 0640;
} // namespace

DlpLinkFile::DlpLinkFile(std::string dlpLinkName, std::shared_ptr<DlpFile> dlpFile)
    :dlpLinkName_(dlpLinkName), dlpFile_(dlpFile), refcount_(1)
{
    (void)memset_s(&fileStat_, sizeof(fileStat_), 0, sizeof(fileStat_));
    fileStat_.st_ino = GetFileInode(this);
    fileStat_.st_mode = S_IFREG | DEFAULT_INODE_ACCESS;
    fileStat_.st_nlink = 1;
    fileStat_.st_uid = getuid();
    fileStat_.st_gid = getgid();

    UpdateCurrTimeStat(&fileStat_.st_atim);
    UpdateCurrTimeStat(&fileStat_.st_mtim);
    UpdateCurrTimeStat(&fileStat_.st_ctim);
}

DlpLinkFile::~DlpLinkFile()
{
}

bool DlpLinkFile::SubAndCheckZeroRef(int ref)
{
    std::lock_guard<std::mutex> lock(refLock_);
    refcount_ -= ref;
    return (refcount_ <= 0);
}

void DlpLinkFile::IncreaseRef()
{
    std::lock_guard<std::mutex> lock(refLock_);
    if (refcount_ <= 0) {
        return;
    }
    refcount_++;
}

struct stat DlpLinkFile::GetLinkStat()
{
    uint32_t res = dlpFile_->GetFsContentSize();
    if (res != INVALID_FILE_SIZE) {
        fileStat_.st_size = res;
    }
    return fileStat_;
}

int32_t DlpLinkFile::Truncate(off_t modifySize)
{
    if (modifySize > INVALID_FILE_SIZE || modifySize < 0) {
        DLP_LOG_ERROR(LABEL, "Modify size is invalid");
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Link dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    int32_t res = dlpFile_->Truncate(static_cast<uint32_t>(modifySize));
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Link dlp file truncate failed, res %{public}d.", res);
    } else {
        DLP_LOG_INFO(LABEL, "Link dlp file truncate size %{public}u ok.", static_cast<uint32_t>(modifySize));
    }
    UpdateMtimeStat();
    return res;
}

void DlpLinkFile::UpdateAtimeStat()
{
    UpdateCurrTimeStat(&fileStat_.st_atim);
}

void DlpLinkFile::UpdateMtimeStat()
{
    UpdateCurrTimeStat(&fileStat_.st_mtim);
}

int32_t DlpLinkFile::Write(uint32_t offset, void* buf, uint32_t size)
{
    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "no dlp file to write");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    int32_t res = dlpFile_->DlpFileWrite(offset, buf, size);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "link file write failed, res %{public}d.", res);
    }
    UpdateMtimeStat();
    return res;
}

int32_t DlpLinkFile::Read(uint32_t offset, void* buf, uint32_t size)
{
    DLP_LOG_DEBUG(LABEL, "read offset %{public}u size %{public}u", offset, size);
    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "no dlp file to read");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    UpdateAtimeStat();
    return dlpFile_->DlpFileRead(offset, buf, size);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
