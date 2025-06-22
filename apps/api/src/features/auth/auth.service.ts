import {
  AuthTokensInterface,
  LoginUserInterface,
  RefreshTokenInterface,
  RegisterUserInterface,
} from '@/common/interfaces';
import {
  Env,
  extractName,
  generateOTP,
  generateRefreshTime,
  hashString,
  validateString,
} from '@/common/utils';
import { TransactionService } from '@/database';
import {
  ChangePasswordDto,
  ConfirmEmailDto,
  CreateUserDto,
  DeleteUserDto,
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

/**
 * Service for handling authentication, registration, session, and user security logic.
 */
@Injectable()
export class AuthService {
  /**
   * Creates an instance of AuthService.
   *
   * @param {JwtService} jwtService - JWT service for token operations.
   * @param {ConfigService<Env>} config - Configuration service for environment variables.
   * @param {Repository<User>} UserRepository - Repository for user entities.
   * @param {Repository<Profile>} profileRepository - Repository for profile entities.
   * @param {Repository<Session>} SessionRepository - Repository for session entities.
   * @param {Repository<Otp>} OtpRepository - Repository for OTP entities.
   * @param {TransactionService} transactionService - TransactionService to run typeorm query
   * @param {MailService} mailService - Service for sending emails.
   * @param {Logger} logger - Logger instance.
   */
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
    private readonly transactionService: TransactionService,
    private readonly mailService: MailService,
    private readonly logger: Logger,
  ) {}

  /**
   * Generates access and refresh tokens for a user.
   *
   * @param {User} user - User entity.
   * @returns {Promise<AuthTokensInterface>} Object containing access and refresh tokens.
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
   * Validates a user with identifier and password.
   *
   * @param {ValidateUserDto} dto - Validation DTO containing identifier and password.
   * @returns {Promise<User>} The validated user entity.
   * @throws {NotFoundException} If user is not found.
   * @throws {UnauthorizedException} If credentials are invalid.
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
   * Registers a new user account with email and password.
   *
   * @param {CreateUserDto} createUserDto - Data for creating a new user.
   * @returns {Promise<RegisterUserInterface>} Registered user data.
   * @throws {BadRequestException} If registration fails.
   */
  async register(createUserDto: CreateUserDto): Promise<RegisterUserInterface> {
    const email_confirmation_otp = await generateOTP();
    try {
      const result = await this.transactionService.runInTransaction(
        async (manager) => {
          const user = manager.create(User, createUserDto);
          await manager.insert(User, user);

          const profile = manager.create(Profile, {
            user_id: user.id,
            name: extractName(createUserDto.email),
          });
          await manager.insert(Profile, profile);

          const otp = manager.create(Otp, {
            otp: email_confirmation_otp,
            type: 'EMAIL_CONFIRMATION',
            expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
          });
          await manager.insert(Otp, otp);

          return { user, profile, otp };
        },
      );

      await this.mailService.sendEmail({
        to: [result.user.email],
        subject: 'Confirm your email',
        html: RegisterSuccessMail({
          name: result.profile.name,
          otp: email_confirmation_otp,
        }),
      });
      return { data: result.user };
    } catch (e) {
      this.logger.error(e);
      throw new BadRequestException('Something went wrong!');
    }
  }

  /**
   * Signs in a user account.
   *
   * @param {SignInUserDto} dto - Sign-in DTO.
   * @returns {Promise<LoginUserInterface>} Login response with user data and tokens.
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
    const session_refresh_time = await generateRefreshTime();
    return {
      data: user,
      tokens: { ...tokens, session_token: session.id, session_refresh_time },
    };
  }

  /**
   * Confirms the user's email account.
   *
   * @param {ConfirmEmailDto} dto - Confirmation DTO.
   * @returns {Promise<void>}
   * @throws {NotFoundException} If user or OTP is not found.
   * @throws {BadRequestException} If the confirmation code is invalid or expired.
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
   * Sends a password reset token to the user's email.
   *
   * @param {ForgotPasswordDto} dto - Forgot password DTO.
   * @returns {Promise<void>}
   * @throws {NotFoundException} If user is not found.
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
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
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
   * Resets the user's password using a reset token.
   *
   * @param {ResetPasswordDto} dto - Reset password DTO.
   * @returns {Promise<void>}
   * @throws {NotFoundException} If user or OTP is not found.
   * @throws {BadRequestException} If the reset token is invalid or expired.
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
   * Changes the user's password.
   *
   * @param {ChangePasswordDto} dto - Change password DTO.
   * @returns {Promise<void>}
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
   * Signs out the user from the current session.
   *
   * @param {SignOutUserDto} dto - Sign out DTO.
   * @returns {Promise<void>}
   * @throws {NotFoundException} If session is not found.
   */
  async signOut(dto: SignOutUserDto): Promise<void> {
    const session = await this.SessionRepository.findOne({
      where: { id: dto.session_token },
    });
    if (!session) throw new NotFoundException('Session not found');
    await this.SessionRepository.remove(session);
  }

  /**
   * Signs out the user from all devices by user ID.
   *
   * @param {SignOutAllDeviceUserDto} dto - Sign out all devices DTO.
   * @returns {Promise<void>}
   */
  async signOutAllDevices(dto: SignOutAllDeviceUserDto): Promise<void> {
    await this.SessionRepository.delete({ user_id: dto.userId });
  }

  /**
   * Refreshes the user's access token.
   *
   * @param {RefreshTokenDto} dto - Refresh token DTO.
   * @returns {Promise<RefreshTokenInterface>} New tokens and session info.
   * @throws {NotFoundException} If user or session is not found.
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
   * Retrieves all sessions for a user by user ID.
   *
   * @param {string} userId - User ID.
   * @returns {Promise<Session[]>} List of sessions.
   */
  async getSessions(userId: string): Promise<Session[]> {
    return await this.SessionRepository.find({
      where: {
        user_id: userId,
      },
    });
  }

  /**
   * Retrieves a session by session ID.
   *
   * @param {string} id - Session ID.
   * @returns {Promise<Session>} Session entity.
   * @throws {NotFoundException} If session is not found.
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

  /**
   * Deletes a user account.
   *
   * @param {DeleteUserDto} dto - Delete user DTO.
   * @returns {Promise<void>}
   * @throws {NotFoundException} If user is not found.
   * @throws {BadRequestException} If credentials are invalid or deletion fails.
   */
  async deleteAccount(dto: DeleteUserDto): Promise<void> {
    const user = await this.UserRepository.findOne({
      where: { id: dto.user_id },
    });
    if (!user) throw new NotFoundException('User not found');
    const isValidPassword = validateString(dto.password, user.password);
    if (!isValidPassword) throw new BadRequestException('Invalid credentials');
    try {
      await this.UserRepository.remove(user);
    } catch (e) {
      throw new BadRequestException(e);
    }
  }
}
