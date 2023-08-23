import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import hilog from '@ohos.hilog';
import UIAbility from '@ohos.app.ability.UIAbility';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import dlpPermission from '@ohos.dlpPermission';
import {terminateSelfWithResult} from '../common/utils';

const TAG = "DLP_XTS_SetRetentionStatePromise";

export default class SetRetentionStatePromise extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    globalThis.context = this.context;
    globalThis.want = want;
  }

  onDestroy() {
  }

  async onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    var success = <boolean> globalThis.want.parameters['ohos.dlp.params.success'];
    var uriArray=[];
    if(success){
      uriArray = ['uri'];
    }
    try {
      await dlpPermission.setRetentionState(uriArray);
      console.info(TAG, "SetRetentionState promise pass");
      terminateSelfWithResult(0);
    } catch (error) {
      console.error(TAG, "SetRetentionState promise fail", error.code, error.message);
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
