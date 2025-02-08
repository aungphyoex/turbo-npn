import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsEmail, IsString } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'strongPassword123',
  })
  @IsString({
    message: 'Password must be a string',
  })
  password: string;

  @ApiProperty({
    description: 'Username',
    example: 'johndoe',
  })
  @IsString({
    message: 'Username must be a string',
  })
  username: string;

  @ApiProperty({
    description: 'Full name of the user',
    example: 'John Doe',
  })
  @IsString({
    message: 'Name must be a string',
  })
  name: string;

  @ApiProperty({
    description: 'Active status of the user',
    example: true,
  })
  @IsBoolean({
    message: 'Active status must be a boolean',
  })
  isActive: boolean;
}
