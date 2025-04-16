import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class SignOutUserDto {
  @ApiProperty()
  @IsUUID()
  session_token: string;
}
