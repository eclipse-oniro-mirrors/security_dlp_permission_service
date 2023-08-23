import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "GetDLPPermissionInfoPromise";

export default class GetDLPPermissionInfoPromise extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
  }

  onDestroy() {
  }

  async onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    try {
      var dlpPermInfo = await dlpPermission.getDLPPermissionInfo();
      console.info(TAG, "getDLPPermissionInfo promise pass");
      terminateSelfWithResult(0, dlpPermInfo);
    } catch (error) {
      console.error(TAG, "getDLPPermissionInfo promise fail", error.code, error.message);
      terminateSelfWithResult(error.code);
    }
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
