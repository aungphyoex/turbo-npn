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
