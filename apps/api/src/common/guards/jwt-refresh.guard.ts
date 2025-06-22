import { Env } from '@/common/utils';
import { Session } from '@/features/auth/entities/session.entity';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { Repository } from 'typeorm';

/**
 * JWT Refresh Token Guard for validating refresh tokens in a NestJS application.
 * Implements refresh token-based authentication by validating refresh tokens and verifying
 * their existence in the session database. Used for token refresh endpoints to ensure
 * only valid, stored refresh tokens can be used to generate new access tokens.
 */
@Injectable()
export class JwtRefreshGuard implements CanActivate {
  /**
   * Creates an instance of JwtRefreshGuard.
   *
   * @param jwtService - Service for JWT token operations (verify, decode)
   * @param configService - Configuration service for accessing environment variables
   * @param SessionRepository - TypeORM repository for session entity operations
   */
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<Env>,
    @InjectRepository(Session)
    private readonly SessionRepository: Repository<Session>,
  ) {}

  /**
   * Determines if the current request should be allowed to proceed based on refresh token validation.
   * Performs authentication by extracting refresh tokens, verifying token signature,
   * checking token existence in the session database, and attaching user payload to the request object.
   *
   * @param context - The execution context containing request/response information
   * @returns Promise resolving to true if refresh token authentication succeeds
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    console.log(request);
    const token = this.extractTokenFromHeader(request);
    console.log('token', token);
    if (!token) {
      throw new UnauthorizedException('Invalid Refresh Token');
    }
    try {
      request.user = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
      });
      console.log(request.user);
    } catch (error) {
      throw new UnauthorizedException('Invalid Refresh Token');
    }
    console.log('request.body', request.body);
    console.log('request.user', request.user);
    const session = await this.SessionRepository.findOne({
      where: {
        refresh_token: token,
        user_id: request.user.id,
      },
    });
    console.log('session', session);
    if (!session) throw new UnauthorizedException('Invalid Refresh Token');
    return true;
  }

  /**
   * Extracts the JWT refresh token from the Authorization header.
   * Parses the Authorization header expecting "Bearer <token>" format and validates the authorization type.
   *
   * @param request - The Express request object containing headers
   * @returns The JWT refresh token string if found and valid, undefined otherwise
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
