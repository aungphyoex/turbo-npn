import { IsEqualTo } from '@/common/decorators/is-equal-to.decorator';
import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsStrongPassword } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({
    description: 'Current password',
  })
  @IsString()
  @IsNotEmpty()
  currentPassword: string;

  @ApiProperty({
    description: 'New password',
    minimum: 8,
  })
  @IsStrongPassword({
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })
  newPassword: string;

  @ApiProperty({
    description: 'Confirm new password',
    minimum: 8,
  })
  @IsEqualTo('newPassword')
  confirmNewPassword: string;

  user_id: string;
}
