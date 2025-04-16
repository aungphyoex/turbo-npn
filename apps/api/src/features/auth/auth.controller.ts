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
import { SignOutAllDeviceUserDto } from '@/features/auth/dto/signOutAllDevice-user.dto';
import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('sign-up')
  async register(@Body() createUserDto: CreateUserDto) {
    await this.authService.register(createUserDto);
    return {
      message: 'User registered successfully',
    };
  }

  @Public()
  @Post('sign-in')
  async signIn(@Body() signInUserDto: SignInUserDto) {
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

  @Post('sign-out')
  async signOut(@Body() signOutUserDto: SignOutUserDto) {
    await this.authService.signOut(signOutUserDto);
    return { message: 'User signed out successfully' };
  }

  @Post('sign-out-allDevices')
  async signOutAllDevices(
    @Body() signOutAllDeviceDto: SignOutAllDeviceUserDto,
  ) {
    await this.authService.signOutAllDevices(signOutAllDeviceDto);
    return { message: 'User signed out from all devices successfully' };
  }

  @Get('sessions/:userId')
  async sessions(@Param('userId') userId: string) {
    const data = await this.authService.getSessions(userId);
    return {
      data,
    };
  }

  @Get('session/:id')
  async session(@Param('id') id: string) {
    const data = await this.authService.getSession(id);
    return {
      data,
    };
  }

  @Patch('confirm-email')
  async confirmEmail(@Body() confirmEmailDto: ConfirmEmailDto) {
    await this.authService.confirmEmail(confirmEmailDto);
    return { message: 'Email confirmed successfully' };
  }

  @Public()
  @Patch('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.forgotPassword(forgotPasswordDto);
    return { message: 'Password reset link sent to your email' };
  }

  @Public()
  @Patch('reset-password')
  async resetPassword(@Body() changePasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(changePasswordDto);
    return { message: 'Password changed successfully' };
  }

  @Patch('change-password')
  async changePassword(@Body() changePasswordDto: ChangePasswordDto) {
    await this.authService.changePassword(changePasswordDto);
    return { message: 'Password changed successfully' };
  }

  @UseGuards(JwtRefreshGuard)
  @Patch('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const data = await this.authService.refreshToken(refreshTokenDto);
    return {
      message: 'Refresh token generated successfully',
      access_token: data.access_token,
      refresh_token: data.refresh_token,
    };
  }
}
