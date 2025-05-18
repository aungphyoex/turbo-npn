import dayjs from 'dayjs';

/**
 * @description Format date from original date string
 * @param date
 * @param format
 * @returns string
 */
export const formatDate = (
  date: Date | string,
  format = 'MM/DD/YYYY',
): string => {
  return dayjs(date).format(format);
};
