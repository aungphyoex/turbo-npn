/**
 * @description Group array by key
 * @param list
 * @param getKey
 * @return K;
 */

export const groupBy = <T, K extends keyof never>(
  list: Array<T>,
  getKey: (item: T) => K,
) =>
  list.reduce(
    (previous, currentItem) => {
      const group = getKey(currentItem);
      if (!previous[group]) previous[group] = [];
      previous[group].push(currentItem);
      return previous;
    },
    {} as Record<K, T[]>,
  );
