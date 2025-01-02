import { Env, validateString } from '@/common/utils';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { UpdateRefreshTokenDto } from '@/features/auth/dto/update-refresh-token.dto';
import { ValidateUserDto } from '@/features/auth/dto/validate-user.dto';
import AuthTokensInterface from '@/features/auth/interfaces/auth-tokens.interface';
import LoginUserInterface from '@/features/auth/interfaces/login-user.interface';
import RefreshTokenInterface from '@/features/auth/interfaces/refresh-token.interface';
import { CreateUserDto } from '@/features/users/dto/create-user.dto';
import { User } from '@/features/users/entities/user.entity';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<Env>,
    @InjectRepository(User) private readonly UserRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const user = this.UserRepository.create(createUserDto);
      await this.UserRepository.save(user);
      return user;
    } catch {
      throw new BadRequestException(
        'Something went wrong while creating user.',
      );
    }
  }

  async validateUser(dto: ValidateUserDto): Promise<User> {
    const user = await this.UserRepository.findOne({
      where: [{ email: dto.identifier }, { username: dto.identifier }],
    });
    if (!user) throw new NotFoundException('User not found');
    const isValid = await validateString(dto.password, user.password);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async updateRefreshToken(dto: UpdateRefreshTokenDto): Promise<void> {
    dto.user.refreshToken = dto.refresh_token;
    await this.UserRepository.save(dto.user);
  }

  async generateTokens(user: User): Promise<AuthTokensInterface> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: user.id,
          username: user.username,
        },
        {
          secret: this.config.get('ACCESS_TOKEN_SECRET'),
          expiresIn: this.config.get('ACCESS_TOKEN_EXPIRATION'),
        },
      ),
      this.jwtService.signAsync(
        {
          sub: user.id,
          username: user.username,
        },
        {
          secret: this.config.get('REFRESH_TOKEN_SECRET'),
          expiresIn: this.config.get('REFRESH_TOKEN_EXPIRATION'),
        },
      ),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }

  async register(createUserDto: CreateUserDto): Promise<LoginUserInterface> {
    const user = await this.create(createUserDto);
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken({
      refresh_token: tokens.refresh_token,
      user,
    });
    return { data: user, tokens };
  }

  async signIn(dto: SignInUserDto): Promise<LoginUserInterface> {
    const user = await this.validateUser(dto);
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken({
      refresh_token: tokens.refresh_token,
      user,
    });
    return { data: user, tokens };
  }

  async signOut(dto: SignOutUserDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id },
    });
    if (!user) throw new NotFoundException('User not found');
    user.refreshToken = null;
    await this.UserRepository.save(user);
  }

  async refreshToken(dto: RefreshTokenDto): Promise<RefreshTokenInterface> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id, refreshToken: dto.refresh_token },
    });
    if (!user) throw new NotFoundException('User not found');
    const { access_token } = await this.generateTokens(user);
    return {
      access_token,
    };
  }
}
