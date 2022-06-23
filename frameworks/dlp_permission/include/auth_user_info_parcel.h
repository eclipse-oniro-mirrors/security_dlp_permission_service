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

#ifndef AUTH_USER_INFO_PARCEL_H
#define AUTH_USER_INFO_PARCEL_H

#include "dlp_policy.h"
#include "parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct AuthUserInfoParcel final : public Parcelable {
    AuthUserInfoParcel() = default;

    ~AuthUserInfoParcel() override = default;

    bool Marshalling(Parcel& out) const override;

    static AuthUserInfoParcel* Unmarshalling(Parcel& in);

    AuthUserInfo authUserInfo_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // AUTH_USER_INFO_PARCEL_H
