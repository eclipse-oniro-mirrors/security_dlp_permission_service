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

#ifndef INTERFACES_INNER_API_DLP_FILE_DLP_FILE_MANAGER_H
#define INTERFACES_INNER_API_DLP_FILE_DLP_FILE_MANAGER_H

#include <mutex>
#include <unordered_map>
#include <string>
#include "dlp_crypt.h"
#include "dlp_file.h"
#include "dlp_policy.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpFileManager final {
public:
    static DlpFileManager& GetInstance();
    ~DlpFileManager() {};

    std::shared_ptr<DlpFile> GenerateDlpFile(int plainFileFd, int dlpFileFd,
        const DlpProperty& property);
    std::shared_ptr<DlpFile> OpenDlpFile(int dlpFileFd);
    bool IsDlpFile(int dlpFileFd);
    int CloseDlpFile(std::shared_ptr<DlpFile>& dlpFile);
    int RecoverDlpFile(std::shared_ptr<DlpFile>& file, int plainFd);

private:
    DlpFileManager() {};
    DISALLOW_COPY_AND_MOVE(DlpFileManager);

    int AddDlpFileNode(std::shared_ptr<DlpFile>& filePtr);
    int RemoveDlpFileNode(std::shared_ptr<DlpFile>& filePtr);
    std::shared_ptr<DlpFile> GetDlpFile(int dlpFd);
    int GenerateCertData(PermissionPolicy& policy, struct DlpBlob &certData);
    int PrepareDlpEncryptParms(PermissionPolicy& policy, struct DlpBlob& key,
        struct DlpUsageSpec& usage, struct DlpBlob& certData);
    int ParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr);
    void FreeChiperBlob(struct DlpBlob& key, struct DlpBlob& certData, struct DlpUsageSpec& usage);
    int32_t SetDlpFileParams(std::shared_ptr<DlpFile>& filePtr, const DlpProperty& property);

    OHOS::Utils::RWLock g_DlpMapLock_;
    std::unordered_map<int32_t, std::shared_ptr<DlpFile>> g_DlpFileMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_DLP_FILE_MANAGER_H */
