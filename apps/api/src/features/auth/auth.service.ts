import { Env, hashString, validateString } from '@/common/utils';
import { ChangePasswordDto } from '@/features/auth/dto/change-password.dto';
import { ConfirmEmailDto } from '@/features/auth/dto/confirm-email.dto';
import { CreateUserDto } from '@/features/auth/dto/create-user.dto';
import { ForgotPasswordDto } from '@/features/auth/dto/forgot-password.dto';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { ResetPasswordDto } from '@/features/auth/dto/reset-password.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { SignOutAllDeviceUserDto } from '@/features/auth/dto/signOutAllDevice-user.dto';
import { ValidateUserDto } from '@/features/auth/dto/validate-user.dto';
import { Session } from '@/features/auth/entities/session.entity';
import AuthTokensInterface from '@/features/auth/interfaces/auth-tokens.interface';
import LoginUserInterface from '@/features/auth/interfaces/login-user.interface';
import RefreshTokenInterface from '@/features/auth/interfaces/refresh-token.interface';
import RegisterUserInterface from '@/features/auth/interfaces/register-user.interface';
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
    @InjectRepository(Session)
    private readonly SessionRepository: Repository<Session>,
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

  //Register User Account
  async register(createUserDto: CreateUserDto): Promise<RegisterUserInterface> {
    const emailVerificationToken = await this.generateOTP();
    const user = await this.create({
      ...createUserDto,
      emailVerificationToken,
      emailVerificationTokenExpires: new Date(
        Date.now() + 1000 * 60 * 60 * 24, // 1 day
      ),
    });
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Confirm your email',
      html: RegisterMail({
        name: user.name,
        code: emailVerificationToken,
      }),
    });
    return { data: user };
  }

  //Sign In User Account
  async signIn(dto: SignInUserDto): Promise<LoginUserInterface> {
    const user = await this.validateUser(dto);
    const tokens = await this.generateTokens(user);
    const sessionData = this.SessionRepository.create({
      user_id: user.id,
      refresh_token: tokens.refresh_token,
      ip: dto.ip,
      device_name: dto.device_name,
      device_os: dto.device_os,
      browser: dto.browser,
      location: dto.location,
      userAgent: dto.userAgent,
    });
    const session = await this.SessionRepository.save(sessionData);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Login Detected',
      html: SignInMail({
        name: user.name,
      }),
    });
    return { data: user, tokens: { ...tokens, session_token: session.id } };
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
    const user = await this.findUser(dto.identifier);
    if (!user) throw new NotFoundException('User not found');
    if (user.passwordResetToken !== dto.resetToken)
      throw new BadRequestException('Invalid password reset token');
    if (
      user.passwordResetTokenExpires &&
      new Date() > user.passwordResetTokenExpires
    )
      throw new BadRequestException('Password reset token expired');
    user.password = await hashString(dto.newPassword);
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
    user.password = await hashString(dto.newPassword);
    await this.UserRepository.save(user);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Password Change Successful',
      html: ChangePasswordMail({
        name: user.name,
      }),
    });
  }

  //Sign Out User Account
  async signOut(dto: SignOutUserDto): Promise<void> {
    const session = await this.SessionRepository.findOne({
      where: { id: dto.session_token },
    });
    if (!session) throw new NotFoundException('Session not found');
    await this.SessionRepository.remove(session);
  }

  //Sign Out All Device By User ID
  async signOutAllDevices(dto: SignOutAllDeviceUserDto): Promise<void> {
    await this.SessionRepository.delete({ user_id: dto.userId });
  }

  //Refresh User Access Token
  async refreshToken(dto: RefreshTokenDto): Promise<RefreshTokenInterface> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id },
    });
    if (!user) throw new NotFoundException('User not found');
    const { access_token, refresh_token } = await this.generateTokens(user);
    const session = await this.SessionRepository.findOne({
      where: {
        id: dto.session_token,
        user_id: dto.user_id,
      },
    });
    if (!session) throw new NotFoundException('Session not found');
    session.refresh_token = refresh_token;
    await this.SessionRepository.save(session);
    return {
      access_token,
      refresh_token,
    };
  }

  //Get Auth Sessions
  async getSessions(userId: string): Promise<Session[]> {
    return await this.SessionRepository.find({
      where: {
        user_id: userId,
      },
    });
  }

  //Get Auth Session By Session ID
  async getSession(id: string): Promise<Session> {
    const session = await this.SessionRepository.findOne({
      where: {
        id: id,
      },
    });
    if (!session) throw new NotFoundException('Session not found!');
    return session;
  }
}
