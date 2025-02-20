import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty()
  @IsString({
    message: 'Identifier must be a string',
  })
  identifier: string;

  @ApiProperty()
  @IsString({
    message: 'Password must be a string',
  })
  password: string;

  @ApiProperty()
  @IsString({
    message: 'New password must be a string',
  })
  newPassword: string;
}
