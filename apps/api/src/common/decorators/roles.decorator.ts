import { SetMetadata } from '@nestjs/common';
import { Role } from '../constants';

/**
 * Metadata key used to store required roles for a route or controller.
 * @type {string}
 */
export const ROLES_KEY: string = 'roles';

/**
 * Decorator to specify required roles for a route or controller.
 *
 * @param {Role[]} roles - Array of roles that are permitted to access the route.
 * @returns {MethodDecorator & ClassDecorator} Decorator function to set the roles metadata.
 */
export const Roles = (...roles: Role[]): MethodDecorator & ClassDecorator =>
  SetMetadata(ROLES_KEY, roles);
