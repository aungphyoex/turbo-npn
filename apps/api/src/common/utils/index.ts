export const isEmptyObj = (obj: object) =>
  Object.keys(obj).length === 0 && obj.constructor === Object;

export const concatStr = (
  strings: (number | string)[],
  divider?: string,
): string => strings.join(divider ?? ' ');

export const getRandomInt = (min: number, max: number) => {
  const minCelled = Math.ceil(min),
    maxFloored = Math.floor(max);
  return Math.floor(Math.random() * (maxFloored - minCelled) + minCelled); // The maximum is exclusive and the minimum is inclusive
};

export function extractName(email: string): string {
  const username = email.split('@')[0];
  return username.replace(/\d+$/, '');
}

export const generateRefreshTime = async (day = 3): Promise<string> => {
  const threeDays = day * 24 * 60 * 60 * 1000; // 3 days in milliseconds
  const refreshTime = new Date(Date.now() + threeDays);
  return refreshTime.toISOString();
};

export * from './amazon-s3';
export * from './file';
export * from './file-s3';
export * from './hashString';
export * from './otp';
export * from './validateEnv';
