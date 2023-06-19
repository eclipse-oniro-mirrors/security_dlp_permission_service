/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OPEN_DLP_FILE_CALLBACK_INFO_PARCEL_H
#define OPEN_DLP_FILE_CALLBACK_INFO_PARCEL_H

#include "open_dlp_file_callback_info.h"
#include "parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct OpenDlpFileCallbackInfoParcel final : public Parcelable {
public:
    OpenDlpFileCallbackInfoParcel() = default;

    ~OpenDlpFileCallbackInfoParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static OpenDlpFileCallbackInfoParcel* Unmarshalling(Parcel& in);

    OpenDlpFileCallbackInfo fileInfo;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // OPEN_DLP_FILE_CALLBACK_INFO_PARCEL_H
