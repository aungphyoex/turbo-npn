import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Custom parameter decorator to extract the client's IP address from the request.
 *
 * This decorator retrieves the IP address from the 'x-forwarded-for' header if present,
 * otherwise falls back to the remote address from the connection object.
 *
 * @param data - Not used, but required by the decorator signature.
 * @param ctx - The execution context containing the HTTP request.
 * @returns The client's IP address as a string.
 */
export const Ip = createParamDecorator((_, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest();
  return request.headers['x-forwarded-for'] || request.connection.remoteAddress;
});
