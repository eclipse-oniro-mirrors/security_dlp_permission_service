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

#ifndef DLP_FILE_FORMAT_H
#define DLP_FILE_FORMAT_H

#include <stdint.h>
#include "dlp_crypt.h"
#include "nocopyable.h"
#include "rwlock.h"

#ifdef __cplusplus
extern "C" {
#endif
namespace OHOS {
namespace Security {
namespace DlpFormat {
enum DlpOperation {
    DLP_ENCRYPTION = 0,
    DLP_DECRYPTION = 1,
    DLP_UPDATE = 2,
};

#define VALID_IV_SIZE (16)
enum VALID_KEY_SIZE {
    DLP_KEY_LEN_128  = 16,
    DLP_KEY_LEN_192  = 24,
    DLP_KEY_LEN_256  = 32,
};

struct DlpCipher {
    struct DlpBlob encKey;
    struct DlpCipherParam tagIv;
    struct DlpUsageSpec usageSpec;
};

struct DlpEncryptCert {
    uint8_t *certBuff;
};

struct DlpHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t txtOffset;
    uint32_t txtSize;
    uint32_t certOffset;
    uint32_t certSize;
};

class DlpFile {
public:
    DlpFile();
    ~DlpFile();
    int32_t SetCipher(const struct DlpBlob &key, const struct DlpUsageSpec &spec);
    int32_t SetEncryptCert(const struct DlpBlob &data);
    int32_t FileParse(const std::string &inputFileUri);
    int32_t FileParse(int32_t fd);
    int32_t FileParse(const std::string &inputFileUri, struct DlpHeader &head, struct DlpEncryptCert &cert);
    uint32_t GetTxtOffset();
    int32_t Operation(const std::string &inputFileUri, const std::string &outputFileUri, uint32_t op_flag);

private:
    int32_t GenFile(const std::string &inputFileUri, const std::string &outputFileUri, uint32_t op_flag);
    int32_t RemoveDlpPermission(const std::string &inputFileUri, const std::string &outputFileUri);
    struct DlpHeader head_;
    struct DlpEncryptCert cert_;
    struct DlpCipher cipher_;
};
}  // namespace DlpFormat
}  // namespace Security
}  // namespace OHOS
#ifdef __cplusplus
}
#endif

#endif
