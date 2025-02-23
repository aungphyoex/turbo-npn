export const objectToFormData = (data: Record<string, unknown>): FormData => {
  const formData = new FormData();

  const appendValue = (key: string, value: unknown) => {
    if (value instanceof File || value instanceof Blob) {
      formData.append(key, value);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item instanceof File || item instanceof Blob) {
          formData.append(`${key}`, item);
        } else {
          formData.append(`${key}[${index}]`, item.toString());
        }
      });
    } else if (
      value &&
      typeof value === 'object' &&
      !(value instanceof File) &&
      !(value instanceof Blob)
    ) {
      // Handle nested objects
      Object.entries(value as Record<string, unknown>).forEach(
        ([nestedKey, nestedValue]) => {
          appendValue(`${key}[${nestedKey}]`, nestedValue);
        },
      );
    } else if (value !== undefined && value !== null) {
      formData.append(key, String(value));
    }
  };

  Object.entries(data).forEach(([key, value]) => {
    appendValue(key, value);
  });

  return formData;
};
