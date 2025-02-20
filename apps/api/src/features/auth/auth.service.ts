import { Env, validateString } from '@/common/utils';
import { ChangePasswordDto } from '@/features/auth/dto/change-password.dto';
import { ConfirmEmailDto } from '@/features/auth/dto/confirm-email.dto';
import { CreateUserDto } from '@/features/auth/dto/create-user.dto';
import { ForgotPasswordDto } from '@/features/auth/dto/forgot-password.dto';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { ResetPasswordDto } from '@/features/auth/dto/reset-password.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { UpdateRefreshTokenDto } from '@/features/auth/dto/update-refresh-token.dto';
import { ValidateUserDto } from '@/features/auth/dto/validate-user.dto';
import AuthTokensInterface from '@/features/auth/interfaces/auth-tokens.interface';
import LoginUserInterface from '@/features/auth/interfaces/login-user.interface';
import RefreshTokenInterface from '@/features/auth/interfaces/refresh-token.interface';
import { MailService } from '@/features/mail/mail.service';
import ChangePasswordMail from '@/features/mail/templates/change-password.mail';
import ConfirmEmailMail from '@/features/mail/templates/confirm-email.mail';
import ForgotPasswordMail from '@/features/mail/templates/forgot-password.mail';
import RegisterMail from '@/features/mail/templates/register.mail';
import SignInMail from '@/features/mail/templates/sign-in.mail';
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
import crypto from 'crypto';
import { Repository } from 'typeorm';
@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<Env>,
    @InjectRepository(User) private readonly UserRepository: Repository<User>,
    private readonly mailService: MailService,
  ) {}

  //Generate Tokens
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

  //Generate OTP Code For Email Confirmation
  async generateOTP(length = 6): Promise<string> {
    return crypto
      .randomInt(0, 10 ** length)
      .toString()
      .padStart(length, '0');
  }

  //Create User
  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const user = this.UserRepository.create(createUserDto);
      await this.UserRepository.insert(user);
      return user;
    } catch {
      throw new BadRequestException(
        'Something went wrong while creating user.',
      );
    }
  }

  //Find User
  async findUser(identifier: string): Promise<User | null> {
    return await this.UserRepository.findOne({
      where: [{ email: identifier }, { username: identifier }],
    });
  }

  //Check User Is Already Exists
  async validateUser(dto: ValidateUserDto): Promise<User> {
    const user = await this.findUser(dto.identifier);
    if (!user) throw new NotFoundException('User not found');
    const isValid = await validateString(dto.password, user.password);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  //Update Refresh Token
  async updateRefreshToken(dto: UpdateRefreshTokenDto): Promise<void> {
    dto.user.refreshToken = dto.refresh_token;
    await this.UserRepository.save(dto.user);
  }

  //Register User Account
  async register(createUserDto: CreateUserDto): Promise<LoginUserInterface> {
    const emailVerificationToken = await this.generateOTP();
    const user = await this.create({
      ...createUserDto,
      emailVerificationToken,
      emailVerificationTokenExpires: new Date(
        Date.now() + 1000 * 60 * 60 * 24, // 1 day
      ),
    });
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken({
      refresh_token: tokens.refresh_token,
      user,
    });
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Confirm your email',
      html: RegisterMail({
        name: user.name,
        code: emailVerificationToken,
      }),
    });
    return { data: user, tokens };
  }

  //Sign In User Account
  async signIn(dto: SignInUserDto): Promise<LoginUserInterface> {
    const user = await this.validateUser(dto);
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken({
      refresh_token: tokens.refresh_token,
      user,
    });
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'SignIn With Your Email',
      html: SignInMail({
        name: user.name,
      }),
    });
    return { data: user, tokens };
  }

  //Confirm User Email
  async confirmEmail(dto: ConfirmEmailDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { email: dto.email },
    });
    if (!user) throw new NotFoundException('User not found');
    if (user.emailVerificationToken !== dto.code)
      throw new BadRequestException('Invalid confirmation code');
    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationTokenExpires = null;
    await this.UserRepository.save(user);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Confirmation Successful',
      html: ConfirmEmailMail({
        name: user.name,
      }),
    });
  }

  //Forgot Password
  async forgotPassword(dto: ForgotPasswordDto): Promise<void> {
    const user = await this.findUser(dto.identifier);
    if (!user) throw new NotFoundException('User not found');
    const passwordResetToken = await this.generateOTP();
    user.passwordResetToken = passwordResetToken;
    user.passwordResetTokenExpires = new Date(
      Date.now() + 1000 * 60 * 60 * 24, // 1 day
    );
    await this.UserRepository.save(user);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Reset Password',
      html: ForgotPasswordMail({
        name: user.name,
        code: passwordResetToken,
      }),
    });
  }

  //Reset Password
  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.identifier },
    });
    if (!user) throw new NotFoundException('User not found');
    if (user.passwordResetToken !== dto.resetToken)
      throw new BadRequestException('Invalid password reset token');
    if (
      user.passwordResetTokenExpires &&
      new Date() > user.passwordResetTokenExpires
    )
      throw new BadRequestException('Password reset token expired');
    user.password = dto.newPassword;
    user.passwordResetToken = null;
    user.passwordResetTokenExpires = null;
    await this.UserRepository.save(user);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Password Reset Successful',
      html: ChangePasswordMail({
        name: user.name,
      }),
    });
  }

  //Change Password
  async changePassword(dto: ChangePasswordDto): Promise<void> {
    const user = await this.validateUser(dto);
    user.password = dto.newPassword;
    await this.UserRepository.save(user);
  }

  //Sign Out User Account
  async signOut(dto: SignOutUserDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id },
    });
    if (!user) throw new NotFoundException('User not found');
    user.refreshToken = null;
    await this.UserRepository.save(user);
  }

  //Refresh User Access Token
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
