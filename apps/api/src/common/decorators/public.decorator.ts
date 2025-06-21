import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key used to mark a route as public (no authentication required).
 *
 * @type {string}
 */
export const IS_PUBLIC_KEY: string = 'isPublic';

/**
 * Custom decorator to mark a route or controller as public.
 *
 * When applied, this decorator sets the 'isPublic' metadata to true,
 * allowing guards (such as authentication guards) to bypass authentication for the route.
 *
 * @returns {MethodDecorator & ClassDecorator} A decorator function to set the public metadata.
 */
export const Public = (): MethodDecorator & ClassDecorator =>
  SetMetadata(IS_PUBLIC_KEY, true);
