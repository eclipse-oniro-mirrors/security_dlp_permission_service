import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "IsInSandboxPromise";

export default class IsInSandboxCallback extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
  }

  onDestroy() {
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    dlpPermission.isInSandbox(async (error, isInSandbox) => {
      if (error) {
        console.error(TAG, "isInSandbox callback fail", error.code, error.message);
        terminateSelfWithResult(error.code);
      } else {
        if (isInSandbox == true) {
          console.info(TAG, "isInSandbox callback pass");
          terminateSelfWithResult(0);
        } else {
          console.error(TAG, "isInSandbox callback fail");
          terminateSelfWithResult(-1);
        }
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
