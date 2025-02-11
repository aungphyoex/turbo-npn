import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

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
  username: string;

  @ApiProperty()
  @IsString({
    message: 'Name must be a string',
  })
  name: string;
}
