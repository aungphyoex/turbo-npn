import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ValidateUserDto {
  @ApiProperty()
  @IsString({
    message: 'First name must be a string',
  })
  identifier: string;

  @ApiProperty()
  @IsString({
    message: 'Password must be a string',
  })
  password: string;
}
