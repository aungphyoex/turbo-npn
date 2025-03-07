import dayjs from 'dayjs';

export const formatDate = (
  date: Date | string,
  format = 'MM/DD/YYYY',
): string => {
  return dayjs(date).format(format);
};
