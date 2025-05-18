'use server';

import { safeFetch } from '@/lib/safeFetch';
import {
  GetAllUsers,
  GetAllUsersSchema,
  GetUserSchema,
  User,
} from '@/types/user.type';

/**
 * @description Get all users
 * @returns GetAllUsers
 */
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

/**
 * @description Get user by identifier (Email or Username)
 * @param identifier
 * @returns User | null
 */
export const getUser = async (identifier: string): Promise<User | null> => {
  const [error, data] = await safeFetch(GetUserSchema, `/users/${identifier}`, {
    cache: 'no-store',
  });
  if (error) {
    console.log('Get user error', error);
    return null;
  }
  return data.data;
};
