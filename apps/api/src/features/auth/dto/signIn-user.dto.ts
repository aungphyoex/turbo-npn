import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class SignInUserDto {
  @ApiProperty({
    description: 'Email or username to sign in',
    example: 'user@example.com',
  })
  @IsString({
    message: 'Identifier must be a string',
  })
  identifier: string;

  @ApiProperty({
    description: 'User password',
    example: 'strongPassword123',
  })
  @IsString({
    message: 'Password must be a string',
  })
  password: string;
}
