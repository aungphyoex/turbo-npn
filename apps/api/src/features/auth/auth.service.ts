import {
  Env,
  extractName,
  generateOTP,
  generateRefreshTime,
  hashString,
  validateString,
} from '@/common/utils';
import {
  AuthTokensInterface,
  LoginUserInterface,
  RefreshTokenInterface,
  RegisterUserInterface,
} from '@/features/auth/auth.interface';
import {
  ChangePasswordDto,
  ConfirmEmailDto,
  CreateUserDto,
  ForgotPasswordDto,
  RefreshTokenDto,
  ResetPasswordDto,
  SignInUserDto,
  SignOutAllDeviceUserDto,
  SignOutUserDto,
  ValidateUserDto,
} from '@/features/auth/dto';
import { Otp } from '@/features/auth/entities/otp.entity';
import { Session } from '@/features/auth/entities/session.entity';
import { MailService } from '@/features/mail/mail.service';
import {
  ChangePasswordSuccessMail,
  ConfirmEmailSuccessMail,
  RegisterSuccessMail,
  ResetPasswordMail,
  SignInSuccessMail,
} from '@/features/mail/templates';
import { Profile } from '@/features/users/entities/profile.entity';
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
import { Logger } from 'nestjs-pino';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<Env>,
    @InjectRepository(User)
    private readonly UserRepository: Repository<User>,
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
    @InjectRepository(Session)
    private readonly SessionRepository: Repository<Session>,
    @InjectRepository(Otp)
    private readonly OtpRepository: Repository<Otp>,
    private readonly mailService: MailService,
    private readonly logger: Logger,
  ) {}

  /**
   * @description Generate Refresh Token and Access Token
   * @param user
   * @return Promise<AuthTokensInterface>
   */
  async generateTokens(user: User): Promise<AuthTokensInterface> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          username: user.username,
          email: user.email,
          id: user.id,
        },
        {
          secret: this.config.get('ACCESS_TOKEN_SECRET'),
          expiresIn: this.config.get('ACCESS_TOKEN_EXPIRATION'),
        },
      ),
      this.jwtService.signAsync(
        {
          username: user.username,
          email: user.email,
          id: user.id,
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

  /**
   * @description Validate User with identifier and password
   * @param dto
   * @return Promise<User>
   */
  async validateUser(dto: ValidateUserDto): Promise<User> {
    const user = await this.UserRepository.findOne({
      where: [{ email: dto.identifier }, { username: dto.identifier }],
      relations: ['profile'],
    });
    if (!user) throw new NotFoundException('User not found');
    const isValid = await validateString(dto.password, user.password);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  /**
   * @description Register user account with email and password
   * @param createUserDto
   * @return Promise<RegisterUserInterface>
   */
  async register(createUserDto: CreateUserDto): Promise<RegisterUserInterface> {
    const email_confirmation_otp = await generateOTP();
    // Create and insert user
    try {
      const user = this.UserRepository.create(createUserDto);
      await this.UserRepository.insert(user);
      const profile = this.profileRepository.create({
        user_id: user.id,
        name: extractName(createUserDto.email),
      });
      await this.profileRepository.insert(profile);
      const token = this.OtpRepository.create({
        otp: email_confirmation_otp,
        type: 'EMAIL_CONFIRMATION',
        expires: new Date(
          Date.now() + 1000 * 60 * 60 * 24, // 1 day
        ),
      });
      await this.OtpRepository.save(token);
      await this.mailService.sendEmail({
        to: [user.email],
        subject: 'Confirm your email',
        html: RegisterSuccessMail({
          name: profile.name,
          otp: email_confirmation_otp,
        }),
      });
      return { data: user };
    } catch (e) {
      this.logger.error(e);
      throw new BadRequestException('Something went wrong!');
    }
  }

  /**
   * @description SignIn User Account
   * @param dto
   * @return Promise<LoginUserInterface>
   */
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
      subject: 'SignIn with your email',
      html: SignInSuccessMail({
        username: user.profile.name,
        loginTime: sessionData.createdAt,
        ipAddress: session.ip,
        location: session.location,
        device: session.device_name,
      }),
    });
    const session_refresh_time = await generateRefreshTime(); //3 days default
    return {
      data: user,
      tokens: { ...tokens, session_token: session.id, session_refresh_time },
    };
  }

  /**
   * @description Confirm Email Account
   * @param dto
   * @return Promise<void>
   */
  async confirmEmail(dto: ConfirmEmailDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { email: dto.email },
      relations: ['profile'],
    });
    if (!user) throw new NotFoundException('User not found');
    const otp = await this.OtpRepository.findOne({
      where: { otp: dto.token, type: 'EMAIL_CONFIRMATION' },
    });
    if (!otp) throw new NotFoundException('Invalid confirmation code');
    if (otp.otp !== dto.token)
      throw new BadRequestException('Invalid confirmation code');
    if (otp.expires && new Date(otp.expires) < new Date())
      throw new BadRequestException('Email confirm token expired');
    user.isEmailVerified = true;
    user.emailVerifiedAt = new Date();
    await this.UserRepository.save(user);
    await this.OtpRepository.remove(otp);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Confirmation Successful',
      html: ConfirmEmailSuccessMail({
        name: user.profile.name,
      }),
    });
  }

  /**
   * @description Forgot your password, to get your password reset token
   * @param dto
   * @return Promise<void>
   */
  async forgotPassword(dto: ForgotPasswordDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: [{ email: dto.identifier }, { username: dto.identifier }],
      relations: ['profile'],
    });
    if (!user) throw new NotFoundException('User not found');
    const passwordResetToken = await generateOTP();
    const otp = this.OtpRepository.create({
      otp: passwordResetToken,
      type: 'PASSWORD_RESET',
      expires: new Date(
        Date.now() + 1000 * 60 * 60 * 24, // 1 day
      ),
    });
    await this.OtpRepository.save(otp);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Reset your password',
      html: ResetPasswordMail({
        name: user.profile.name,
        code: passwordResetToken,
      }),
    });
  }

  /**
   * @description Reset your password with your password reset token
   * @param dto
   * @return Promise<void>
   */
  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: [{ email: dto.identifier }, { username: dto.identifier }],
      relations: ['profile'],
    });
    if (!user) throw new NotFoundException('User not found');
    const otp = await this.OtpRepository.findOne({
      where: { otp: dto.resetToken, type: 'PASSWORD_RESET' },
    });
    if (!otp) throw new NotFoundException('Invalid password reset token');
    if (otp.otp !== dto.resetToken)
      throw new BadRequestException('Invalid password reset token');
    if (otp.otp && new Date() > otp.expires)
      throw new BadRequestException('Password reset token expired');
    user.password = await hashString(dto.newPassword);
    await this.UserRepository.save(user);
    await this.OtpRepository.remove(otp);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Password Reset Successful',
      html: ChangePasswordSuccessMail({
        name: user.profile.name,
      }),
    });
  }

  /**
   * @description Change your password
   * @param dto
   * @return Promise<void>
   */
  async changePassword(dto: ChangePasswordDto): Promise<void> {
    const user = await this.validateUser(dto);
    user.password = await hashString(dto.newPassword);
    await this.UserRepository.save(user);
    await this.mailService.sendEmail({
      to: [user.email],
      subject: 'Password Change Successful',
      html: ChangePasswordSuccessMail({
        name: user.profile.name,
      }),
    });
  }

  /**
   * @description Sign Out User Account
   * @param dto
   * @return Promise<void>
   */
  async signOut(dto: SignOutUserDto): Promise<void> {
    const session = await this.SessionRepository.findOne({
      where: { id: dto.session_token },
    });
    if (!session) throw new NotFoundException('Session not found');
    await this.SessionRepository.remove(session);
  }

  /**
   * @description Sign Out All Device By User ID
   * @param dto
   * @return Promise<void>
   */
  async signOutAllDevices(dto: SignOutAllDeviceUserDto): Promise<void> {
    await this.SessionRepository.delete({ user_id: dto.userId });
  }

  /**
   * @description Refresh User Access Token
   * @param dto
   * @return Promise<RefreshTokenInterface>
   */
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
    const access_token_refresh_time = await generateRefreshTime();
    await this.SessionRepository.save(session);
    return {
      access_token,
      refresh_token,
      session_token: dto.session_token,
      access_token_refresh_time,
    };
  }

  /**
   * @description Get All Sessions By User ID
   * @param userId
   * @return Promise<Session[]>
   */
  async getSessions(userId: string): Promise<Session[]> {
    return await this.SessionRepository.find({
      where: {
        user_id: userId,
      },
    });
  }

  /**
   * @description Get Session By ID
   * @param id
   * @return Promise<Session>
   */
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
