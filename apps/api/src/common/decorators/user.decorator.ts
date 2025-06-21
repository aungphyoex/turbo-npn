import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Custom parameter decorator to extract the user object from the request.
 *
 * @param {unknown} data - Optional data passed to the decorator (not used).
 * @param {ExecutionContext} ctx - The execution context containing the HTTP request.
 * @returns {any} The user object attached to the request.
 */
export const User = createParamDecorator((_, ctx: ExecutionContext): any => {
  const request = ctx.switchToHttp().getRequest();
  return request.user;
});
