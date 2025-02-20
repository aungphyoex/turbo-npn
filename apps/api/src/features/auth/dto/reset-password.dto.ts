import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty()
  @IsString({
    message: 'Identifier must be a string',
  })
  identifier: string;

  @ApiProperty()
  @IsString({
    message: 'Reset Token must be a string',
  })
  resetToken: string;

  @ApiProperty()
  @IsString({
    message: 'New password must be a string',
  })
  newPassword: string;
}
