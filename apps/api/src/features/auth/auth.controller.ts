import { Public } from '@/common/decorators';
import { JwtRefreshGuard } from '@/common/guards/jwt-refresh.guard';
import { ChangePasswordDto } from '@/features/auth/dto/change-password.dto';
import { ConfirmEmailDto } from '@/features/auth/dto/confirm-email.dto';
import { CreateUserDto } from '@/features/auth/dto/create-user.dto';
import { ForgotPasswordDto } from '@/features/auth/dto/forgot-password.dto';
import { RefreshTokenDto } from '@/features/auth/dto/refresh-token.dto';
import { ResetPasswordDto } from '@/features/auth/dto/reset-password.dto';
import { SignInUserDto } from '@/features/auth/dto/signIn-user.dto';
import { SignOutUserDto } from '@/features/auth/dto/signOut-user.dto';
import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';

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

  @Post('confirm-email')
  async confirmEmail(@Body() confirmEmailDto: ConfirmEmailDto) {
    await this.authService.confirmEmail(confirmEmailDto);
    return { message: 'Email confirmed successfully' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.forgotPassword(forgotPasswordDto);
    return { message: 'Password reset link sent to your email' };
  }

  @Post('reset-password')
  async resetPassword(@Body() changePasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(changePasswordDto);
    return { message: 'Password changed successfully' };
  }

  @Post('change-password')
  async changePassword(@Body() changePasswordDto: ChangePasswordDto) {
    await this.authService.changePassword(changePasswordDto);
    return { message: 'Password changed successfully' };
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
}
