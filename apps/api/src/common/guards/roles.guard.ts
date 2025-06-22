import { Role } from '@/common/constants';
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from 'src/common/decorators';

/**
 * Guard that enforces role-based access control for routes in a NestJS application.
 * Uses metadata set by the @Roles() decorator to determine the allowed roles for a route.
 * If the user's role matches one of the required roles, or if the user is a SUPERADMIN,
 * access is granted.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  /**
   * Creates an instance of RolesGuard.
   *
   * @param reflector - NestJS utility for reading metadata from decorators
   */
  constructor(private reflector: Reflector) {}

  /**
   * Determines if the current user has the required role(s) to access the route.
   * Checks the required roles metadata and compares it to the user's role.
   *
   * @param context - The execution context containing request/response information
   * @returns True if the user has one of the required roles or is a SUPERADMIN, false otherwise
   */
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) return true;

    const { user } = context.switchToHttp().getRequest();

    if (user.role === 'SUPERADMIN') return true;

    return requiredRoles.some((role) => user.role === role);
  }
}
