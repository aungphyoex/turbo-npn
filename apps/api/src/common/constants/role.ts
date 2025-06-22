import { z } from 'zod';

/**
 * Zod schema for validating user roles.
 * Accepts only 'ADMIN' or 'USER' as valid role values.
 */
export const roleSchema = z.enum(['ADMIN', 'USER']);

/**
 * Type representing a valid user role.
 *
 * @type {'ADMIN' | 'USER'} Role
 */
export type Role = z.infer<typeof roleSchema>;
