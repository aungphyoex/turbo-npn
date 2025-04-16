import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsString({
    message: 'Password must be a string',
  })
  password: string;

  @ApiProperty()
  @IsString({
    message: 'Username must be a string',
  })
  @IsOptional()
  username: string;

  @ApiProperty()
  @IsOptional()
  @IsString({
    message: 'Name must be a string',
  })
  name: string;

  emailVerificationToken: string | null;

  emailVerificationTokenExpires: Date | null;
}
