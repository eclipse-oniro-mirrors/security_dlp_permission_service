import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "DLP_XTS_GetDLPFileAccessRecordsCallback";

export default class GetDLPFileAccessRecordsCallback extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
  }

  onDestroy() {
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    dlpPermission.getDLPFileAccessRecords(async (error, data) => {
      if (error) {
        console.error(TAG, "getDLPFileAccessRecords callback fail", error.code, error.message);
        terminateSelfWithResult(error.code);
      } else {
        console.info(TAG, "getDLPFileAccessRecords callback pass");
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
