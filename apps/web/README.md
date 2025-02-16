### Frontend

`SafeFetch`

```ts
import z, { ZodSchema } from 'zod';
import { env } from './env';

export const safeFetch = async <T extends ZodSchema<unknown>>(
  schema: T,
  url: URL | RequestInfo,
  init?: RequestInit,
): Promise<[string | null, z.TypeOf<T>]> => {
  const response: Response = await fetch(`${env.API_URL}${url}`, init);
  const res = await response.json();

  if (!response.ok) {
    return [
      `HTTP error! Status: ${response.status} - ${response.statusText}`,
      null,
    ];
  }

  const validateFields = schema.safeParse(res);

  if (!validateFields.success) {
    console.log(res);
    console.log('Validation errors:', validateFields.error);
    return [`Validation error: ${validateFields.error.message}`, null];
  }

  return [null, validateFields.data];
};
```

`How to use SafeFetch?`

```ts
export const getAllUsers = async (): Promise<GetAllUsers> => {
  const [isError, data] = await safeFetch(GetAllUsersSchema, '/users', {
    cache: 'no-store',
  });
  if (isError)
    return {
      data: [],
    };
  return data;
};
```
