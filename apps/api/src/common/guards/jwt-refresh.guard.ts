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

@Injectable()
export class JwtRefreshGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<Env>,
    @InjectRepository(Session)
    private readonly SessionRepository: Repository<Session>,
  ) {}

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

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
