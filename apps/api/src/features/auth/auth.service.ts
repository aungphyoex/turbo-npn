import { Env, validatePasswordComplexity, validateString } from '@/common/utils';
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
import * as crypto from 'crypto';
import { hashString } from '@/common/utils';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<Env>,
    @InjectRepository(User) private readonly UserRepository: Repository<User>,
  ) { }

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
    if (!user.isEmailVerified) throw new UnauthorizedException('Email not verified');
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

  private generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  async sendVerificationEmail(user: User): Promise<void> {
    const token = this.generateToken();
    const expires = new Date();
    expires.setHours(expires.getHours() + 24); // 24 hours expiration

    user.emailVerificationToken = token;
    user.emailVerificationTokenExpires = expires;
    await this.UserRepository.save(user);

    // TODO: Implement email sending logic
    // For now, just console.log the token
    console.log(`Verification token for ${user.email}: ${token}`);
  }

  async verifyEmail(token: string): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: {
        emailVerificationToken: token,
      },
    });

    if (!user) {
      throw new NotFoundException('Invalid verification token');
    }

    const tokenExpires = user.emailVerificationTokenExpires;
    if (!tokenExpires || tokenExpires < new Date()) {
      throw new BadRequestException('Verification token has expired');
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationTokenExpires = null;
    await this.UserRepository.save(user);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const token = this.generateToken();
    const expires = new Date();
    expires.setHours(expires.getHours() + 1); // 1 hour expiration

    user.passwordResetToken = token;
    user.passwordResetTokenExpires = expires;
    await this.UserRepository.save(user);

    // TODO: Implement email sending logic
    // For now, just console.log the token
    console.log(`Password reset token for ${email}: ${token}`);
  }

  async resetPassword(token: string, password: string, confirmPassword: string): Promise<void> {
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    validatePasswordComplexity(password);

    const user = await this.UserRepository.findOne({
      where: {
        passwordResetToken: token,
      },
    });

    if (!user) {
      throw new NotFoundException('Invalid reset token');
    }

    const tokenExpires = user.passwordResetTokenExpires;
    if (!tokenExpires || tokenExpires < new Date()) {
      throw new BadRequestException('Reset token has expired');
    }

    user.password = await hashString(password);
    user.passwordResetToken = null;
    user.passwordResetTokenExpires = null;
    await this.UserRepository.save(user);
  }

  async register(createUserDto: CreateUserDto): Promise<LoginUserInterface> {
    validatePasswordComplexity(createUserDto.password);
    const user = await this.create(createUserDto);
    await this.sendVerificationEmail(user);
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

  async changePassword(dto: ChangePasswordDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isValidPassword = await validateString(dto.currentPassword, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    validatePasswordComplexity(dto.newPassword);

    user.password = await hashString(dto.newPassword);
    await this.UserRepository.save(user);
  }
}
