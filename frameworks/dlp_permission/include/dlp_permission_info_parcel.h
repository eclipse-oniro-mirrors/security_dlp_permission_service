/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DLP_PERMISSION_INFO_PARCEL_H
#define DLP_PERMISSION_INFO_PARCEL_H

#include "auth_user_info_parcel.h"
#include "parcel.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct DLPPermissionInfoParcel final : public Parcelable {
    DLPPermissionInfoParcel() = default;

    ~DLPPermissionInfoParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static DLPPermissionInfoParcel* Unmarshalling(Parcel& in);

    DLPPermissionInfo permInfo_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_INFO_PARCEL_H
