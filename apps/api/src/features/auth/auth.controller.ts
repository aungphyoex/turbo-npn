import { Public } from '@/common/decorators';
import { JwtRefreshGuard } from '@/common/guards/jwt-refresh.guard';
import {
  MessageResponse,
  RefreshTokenResponse,
  SessionResponse,
  SessionsResponse,
  SignInResponse,
} from '@/common/interfaces';
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
} from '@/features/auth/dto';
import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';

/**
 * Controller for handling authentication and user account related endpoints.
 */
@Controller('auth')
export class AuthController {
  /**
   * Creates an instance of AuthController.
   *
   * @param {AuthService} authService - The authentication service.
   */
  constructor(private readonly authService: AuthService) {}

  /**
   * Registers a new user.
   *
   * @param {CreateUserDto} createUserDto - Data for creating a new user.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {SignInUserDto} signInUserDto - User credentials for sign in.
   * @returns {Promise<SignInResponse>} Sign-in response with tokens and user data.
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
   * Signs out the user from the current session.
   *
   * @param {SignOutUserDto} signOutUserDto - Data for signing out.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {SignOutAllDeviceUserDto} dto - Data for signing out from all devices.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {string} userId - ID of the user.
   * @returns {Promise<SessionsResponse>} List of user sessions.
   */
  @Get('sessions/:userId')
  async sessions(@Param('userId') userId: string): Promise<SessionsResponse> {
    const data = await this.authService.getSessions(userId);
    return { data };
  }

  /**
   * Retrieves a session by ID.
   *
   * @param {string} id - Session ID.
   * @returns {Promise<SessionResponse>} Session details.
   */
  @Get('session/:id')
  async session(@Param('id') id: string): Promise<SessionResponse> {
    const data = await this.authService.getSession(id);
    return { data };
  }

  /**
   * Confirms the user's email.
   *
   * @param {ConfirmEmailDto} confirmEmailDto - Email confirmation data.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {ForgotPasswordDto} forgotPasswordDto - Data for password reset request.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {ResetPasswordDto} dto - Data for resetting password.
   * @returns {Promise<MessageResponse>} Response message.
   */
  @Public()
  @Patch('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto): Promise<MessageResponse> {
    await this.authService.resetPassword(dto);
    return { message: 'Password changed successfully' };
  }

  /**
   * Changes the user's password.
   *
   * @param {ChangePasswordDto} dto - Data for changing password.
   * @returns {Promise<MessageResponse>} Response message.
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
   *
   * @param {RefreshTokenDto} dto - Data for refreshing the token.
   * @returns {Promise<RefreshTokenResponse>} Refresh token response.
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

  /**
   * Deletes the user account.
   *
   * @param {DeleteUserDto} deleteUserDto - Data for deleting the user.
   * @returns {Promise<MessageResponse>} Response message.
   */
  @Delete('delete-account')
  async deleteUser(
    @Body() deleteUserDto: DeleteUserDto,
  ): Promise<MessageResponse> {
    await this.authService.deleteAccount(deleteUserDto);
    return { message: 'User deleted successfully' };
  }
}
