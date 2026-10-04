const processValue = (globalThis as { process?: NodeJS.Process }).process ?? {
  arch: "x64",
  platform: "linux",
  env: {},
};

export const arch = processValue.arch;
export const platform = processValue.platform;
export const env = processValue.env;
export default processValue;
