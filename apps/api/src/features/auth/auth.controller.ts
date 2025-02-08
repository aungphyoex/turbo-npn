import { Public } from '@/common/decorators';
import { JwtRefreshGuard } from '@/common/guards/jwt-refresh.guard';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { CreateUserDto } from '@/features/users/dto/create-user.dto';
import { Body, Controller, Post, Request, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    const data = await this.authService.register(createUserDto);
    return {
      message: 'User registered successfully',
      data: data.data,
      tokens: data.tokens,
    };
  }

  @Public()
  @Post('sign-in')
  async signIn(@Body() signInUserDto: SignInUserDto) {
    const data = await this.authService.signIn(signInUserDto);
    return {
      message: 'User signed in successfully',
      data: data.data,
      tokens: data.tokens,
    };
  }

  @Post('sign-out')
  async signOut(@Body() signOutUserDto: SignOutUserDto) {
    await this.authService.signOut(signOutUserDto);
    return { message: 'User signed out successfully' };
  }

  @Public()
  @UseGuards(JwtRefreshGuard)
  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const data = await this.authService.refreshToken(refreshTokenDto);
    return {
      message: 'Refresh token generated successfully',
      access_token: data.access_token,
    };
  }

  @ApiOperation({ summary: 'Verify email address' })
  @ApiResponse({ status: 201, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  @ApiResponse({ status: 404, description: 'Token not found' })
  @Public()
  @Post('verify-email')
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    await this.authService.verifyEmail(verifyEmailDto);
    return { message: 'Email verified successfully' };
  }

  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 201, description: 'Password reset email sent' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.forgotPassword(forgotPasswordDto);
    return { message: 'Password reset instructions sent to your email' };
  }

  @ApiOperation({ summary: 'Reset password with token' })
  @ApiResponse({ status: 201, description: 'Password reset successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  @ApiResponse({ status: 404, description: 'Token not found' })
  @Public()
  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(resetPasswordDto);
    return { message: 'Password reset successfully' };
  }

  @ApiOperation({ summary: 'Change password while authenticated' })
  @ApiResponse({ status: 201, description: 'Password changed successfully' })
  @ApiResponse({ status: 401, description: 'Current password is incorrect' })
  @ApiResponse({
    status: 400,
    description: 'Invalid new password or passwords do not match',
  })
  @ApiBearerAuth()
  @Post('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Request() req,
  ) {
    changePasswordDto.user_id = req.user.sub;
    await this.authService.changePassword(changePasswordDto);
    return { message: 'Password changed successfully' };
  }
}
