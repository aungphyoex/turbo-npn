import { Env } from '@/common/utils';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { IS_PUBLIC_KEY } from 'src/common/decorators';

/**
 * JWT Authentication Guard for protecting routes in a NestJS application.
 * Implements JWT-based authentication by validating access tokens in the Authorization header.
 * Supports public routes through the @Public() decorator and automatically attaches the decoded user payload to the request object.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  /**
   * Creates an instance of JwtAuthGuard.
   *
   * @param jwtService - Service for JWT token operations (verify, decode)
   * @param reflector - NestJS utility for reading metadata from decorators
   * @param configService - Configuration service for accessing environment variables
   */
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    private configService: ConfigService<Env>,
  ) {}

  /**
   * Determines if the current request should be allowed to proceed.
   * Performs authentication by checking for public routes, extracting JWT tokens,
   * verifying tokens, and attaching user payload to the request object.
   *
   * @param context - The execution context containing request/response information
   * @returns Promise resolving to true if authentication succeeds
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    try {
      request.user = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('ACCESS_TOKEN_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid Access Token');
    }
    return true;
  }

  /**
   * Extracts the JWT token from the Authorization header.
   * Parses the Authorization header expecting "Bearer <token>" format and validates the authorization type.
   *
   * @param request - The Express request object containing headers
   * @returns The JWT token string if found and valid, undefined otherwise
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
