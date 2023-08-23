
function terminateSelfWithResult(resultCode: number, info?): void {
  let abilityResult = {
    resultCode: resultCode,
    want: {
      parameters: {
        info: info
      }
    },
  };
  globalThis.context.terminateSelfWithResult(abilityResult);
}

export {
  terminateSelfWithResult
};
