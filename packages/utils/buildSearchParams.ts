/**
 * @description Builds a search params string from an object
 * @param params The object to build the search params from
 * @returns The search params string
 */
export const buildSearchParams = <
  T extends Record<string, string | number | boolean | null | undefined>,
>(
  params: T,
): string => {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, String(value));
    }
  });

  return searchParams.toString();
};
