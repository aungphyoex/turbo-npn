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

import {
  MessageResponse,
  RefreshTokenResponse,
  SessionResponse,
  SessionsResponse,
  SignInResponse,
} from '@/features/auth/auth.interface';
import { ChangePasswordDto } from '@/features/auth/dto/change-password.dto';
import { ConfirmEmailDto } from '@/features/auth/dto/confirm-email.dto';
import { CreateUserDto } from '@/features/auth/dto/create-user.dto';
import { ForgotPasswordDto } from '@/features/auth/dto/forgot-password.dto';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { ResetPasswordDto } from '@/features/auth/dto/reset-password.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { SignOutAllDeviceUserDto } from '@/features/auth/dto/signOutAllDevice-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * @description Registers a new user.
   * @param createUserDto
   * @returns Promise<MessageResponse>
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
   * @description Signs in a user.
   * @param signInUserDto
   * @returns Promise<SignInResponse>
   */
  @Public()
  @Post('sign-in')
  async signIn(@Body() signInUserDto: SignInUserDto): Promise<SignInResponse> {
    const data = await this.authService.signIn(signInUserDto);
    const { password, sessions, ...result } = data.data;

    return {
      message: 'User signed in successfully',
      data: result,
      tokens: data.tokens,
    };
  }

  /**
   * @description Signs out the user from the current session.
   * @param signOutUserDto
   * @returns Promise<MessageResponse>
   */
  @Post('sign-out')
  async signOut(
    @Body() signOutUserDto: SignOutUserDto,
  ): Promise<MessageResponse> {
    await this.authService.signOut(signOutUserDto);
    return { message: 'User signed out successfully' };
  }

  /**
   * @description Signs out the user from all devices.
   * @param dto
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
   * @description Retrieves all sessions for a user.
   * @param userId
   * @returns Promise<SessionsResponse>
   */
  @Get('sessions/:userId')
  async sessions(@Param('userId') userId: string): Promise<SessionsResponse> {
    const data = await this.authService.getSessions(userId);
    return { data };
  }

  /**
   * @description Retrieves a session by ID.
   * @param id
   * @returns Promise<SessionResponse>
   */
  @Get('session/:id')
  async session(@Param('id') id: string): Promise<SessionResponse> {
    const data = await this.authService.getSession(id);
    return { data };
  }

  /**
   * @description Confirms the user's email.
   * @param confirmEmailDto
   * @returns Promise<MessageResponse>
   */
  @Patch('confirm-email')
  async confirmEmail(
    @Body() confirmEmailDto: ConfirmEmailDto,
  ): Promise<MessageResponse> {
    await this.authService.confirmEmail(confirmEmailDto);
    return { message: 'Email confirmed successfully' };
  }

  /**
   * @description Sends a password reset email.
   * @param forgotPasswordDto
   * @returns Promise<MessageResponse>
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
   * @description Resets the user's password using a token.
   * @param dto
   * @returns Promise<MessageResponse>
   */
  @Public()
  @Patch('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<MessageResponse> {
    await this.authService.resetPassword(dto);
    return { message: 'Password changed successfully' };
  }

  /**
   * @description Changes the user's password.
   * @param dto
   * @returns Promise<MessageResponse>
   */
  @Patch('change-password')
  async changePassword(
    @Body() dto: ChangePasswordDto,
  ): Promise<MessageResponse> {
    await this.authService.changePassword(dto);
    return { message: 'Password changed successfully' };
  }

  /**
   * @description Refreshes the access token using a refresh token.
   * @param  dto
   * @returns Promise<RefreshTokenResponse>
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
