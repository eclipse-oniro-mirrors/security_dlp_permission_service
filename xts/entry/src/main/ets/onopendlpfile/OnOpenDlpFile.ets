import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "OnOpenDlpFile";

export default class OnOpenDlpFile extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
  }

  onDestroy() {
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    let func = (dlpFileInfo) => {}
    try {
      dlpPermission.on('openDLPFile', func);
      terminateSelfWithResult(0);
    } catch (err) {
      terminateSelfWithResult(err.code);
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
