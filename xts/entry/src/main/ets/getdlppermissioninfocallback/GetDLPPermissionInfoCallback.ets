import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "GetDLPPermissionInfoCallback";

export default class GetDLPPermissionInfoCallback extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
  }

  onDestroy() {
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    dlpPermission.getDLPPermissionInfo(async (error, dlpPermInfo) => {
      if (error) {
        console.error(TAG, "getDLPPermissionInfo callback fail", error.code, error.message);
        terminateSelfWithResult(error.code);
      } else {
        console.info(TAG, "getDLPPermissionInfo callback pass");
        terminateSelfWithResult(0);
      }
    });
  }

  onWindowStageDestroy() {
    // Main window is destroyed, release UI related resources
  }

  onForeground() {
    // Ability has brought to foreground
  }

  onBackground() {
    // Ability has back to background
  }
}
