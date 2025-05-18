/**
 * @description Sleep util with promise
 * @param ms
 */
export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
