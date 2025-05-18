import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';

import { Public } from '@/common/decorators';
import { JwtRefreshGuard } from '@/common/guards/jwt-refresh.guard';
import { AuthService } from './auth.service';

import { ChangePasswordDto } from '@/features/auth/dto/change-password.dto';
import { ConfirmEmailDto } from '@/features/auth/dto/confirm-email.dto';
import { CreateUserDto } from '@/features/auth/dto/create-user.dto';
import { ForgotPasswordDto } from '@/features/auth/dto/forgot-password.dto';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { ResetPasswordDto } from '@/features/auth/dto/reset-password.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { SignOutAllDeviceUserDto } from '@/features/auth/dto/signOutAllDevice-user.dto';

import {
  MessageResponse,
  RefreshTokenResponse,
  SessionResponse,
  SessionsResponse,
  SignInResponse,
} from '@/features/auth/interfaces/auth-responses.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Registers a new user.
   * @param {CreateUserDto} createUserDto
   * @returns {Promise<MessageResponse>}
   */
  @Public()
  @Post('sign-up')
  async register(
    @Body() createUserDto: CreateUserDto,
  ): Promise<MessageResponse> {
    await this.authService.register(createUserDto);
    return { message: 'User registered successfully' };
  }

  /**
   * Signs in a user.
   * @param {SignInUserDto} signInUserDto
   * @returns {Promise<SignInResponse>}
   */
  @Public()
  @Post('sign-in')
  async signIn(@Body() signInUserDto: SignInUserDto): Promise<SignInResponse> {
    const data = await this.authService.signIn(signInUserDto);
    const { id, name, username, email, isEmailVerified, createdAt, updatedAt } =
      data.data;

    return {
      message: 'User signed in successfully',
      data: {
        id,
        name,
        username,
        email,
        isEmailVerified,
        createdAt,
        updatedAt,
      },
      tokens: data.tokens,
    };
  }

  /**
   * Signs out the user from the current session.
   * @param {SignOutUserDto} signOutUserDto
   * @returns {Promise<MessageResponse>}
   */
  @Post('sign-out')
  async signOut(
    @Body() signOutUserDto: SignOutUserDto,
  ): Promise<MessageResponse> {
    await this.authService.signOut(signOutUserDto);
    return { message: 'User signed out successfully' };
  }

  /**
   * Signs out the user from all devices.
   * @param {SignOutAllDeviceUserDto} dto
   * @returns {Promise<MessageResponse>}
   */
  @Post('sign-out-allDevices')
  async signOutAllDevices(
    @Body() dto: SignOutAllDeviceUserDto,
  ): Promise<MessageResponse> {
    await this.authService.signOutAllDevices(dto);
    return { message: 'User signed out from all devices successfully' };
  }

  /**
   * Retrieves all sessions for a user.
   * @param {string} userId
   * @returns {Promise<SessionsResponse>}
   */
  @Get('sessions/:userId')
  async sessions(@Param('userId') userId: string): Promise<SessionsResponse> {
    const data = await this.authService.getSessions(userId);
    return { data };
  }

  /**
   * Retrieves a session by ID.
   * @param {string} id
   * @returns {Promise<SessionResponse>}
   */
  @Get('session/:id')
  async session(@Param('id') id: string): Promise<SessionResponse> {
    const data = await this.authService.getSession(id);
    return { data };
  }

  /**
   * Confirms the user's email.
   * @param {ConfirmEmailDto} confirmEmailDto
   * @returns {Promise<MessageResponse>}
   */
  @Patch('confirm-email')
  async confirmEmail(
    @Body() confirmEmailDto: ConfirmEmailDto,
  ): Promise<MessageResponse> {
    await this.authService.confirmEmail(confirmEmailDto);
    return { message: 'Email confirmed successfully' };
  }

  /**
   * Sends a password reset email.
   * @param {ForgotPasswordDto} forgotPasswordDto
   * @returns {Promise<MessageResponse>}
   */
  @Public()
  @Patch('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<MessageResponse> {
    await this.authService.forgotPassword(forgotPasswordDto);
    return { message: 'Password reset token sent to your email' };
  }

  /**
   * Resets the user's password using a token.
   * @param {ResetPasswordDto} dto
   * @returns {Promise<MessageResponse>}
   */
  @Public()
  @Patch('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<MessageResponse> {
    await this.authService.resetPassword(dto);
    return { message: 'Password changed successfully' };
  }

  /**
   * Changes the user's password.
   * @param {ChangePasswordDto} dto
   * @returns {Promise<MessageResponse>}
   */
  @Patch('change-password')
  async changePassword(
    @Body() dto: ChangePasswordDto,
  ): Promise<MessageResponse> {
    await this.authService.changePassword(dto);
    return { message: 'Password changed successfully' };
  }

  /**
   * Refreshes the access token using a refresh token.
   * @param {RefreshTokenDto} dto
   * @returns {Promise<RefreshTokenResponse>}
   */
  @UseGuards(JwtRefreshGuard)
  @Patch('refresh-token')
  async refreshToken(
    @Body() dto: RefreshTokenDto,
  ): Promise<RefreshTokenResponse> {
    const data = await this.authService.refreshToken(dto);
    return {
      message: 'Refresh token generated successfully',
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      access_token_refresh_time: data.access_token_refresh_time,
      session_token: data.session_token,
    };
  }
}
