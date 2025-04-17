import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class SignInUserDto {
  @ApiProperty()
  @IsOptional()
  @IsString()
  ip: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  location: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  device_name: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  device_os: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  device_type: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  browser: string;

  @ApiProperty()
  @IsOptional()
  @IsString()
  userAgent: string;

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
}
