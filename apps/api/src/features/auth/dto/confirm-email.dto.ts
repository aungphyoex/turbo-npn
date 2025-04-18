import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class ConfirmEmailDto {
  @ApiProperty()
  @IsString()
  @MaxLength(6)
  @MinLength(6)
  token: string;

  @ApiProperty()
  @IsEmail()
  email: string;
}
