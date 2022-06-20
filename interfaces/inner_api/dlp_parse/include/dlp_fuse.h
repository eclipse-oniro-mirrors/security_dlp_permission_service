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

#ifndef DLP_FUSE_H
#define DLP_FUSE_H
#include <stdint.h>
#include "dlp_crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DLP_FUSE_MAX_BUFFLEN (50 * 1024 * 1024)
int32_t DlpFileRead(int32_t fd, uint32_t offset, void *buf, uint32_t size);
int32_t DlpFileWrite(int32_t fd, uint32_t offset, void *buf, uint32_t size);
int32_t DlpLseek(int32_t fd, uint32_t offset, int32_t whence);
int32_t DlpFileAdd(int32_t fd, struct DlpBlob *key, struct DlpBlob *iv);
int32_t DlpFileDel(int32_t fd);

#ifdef __cplusplus
}
#endif
#endif
