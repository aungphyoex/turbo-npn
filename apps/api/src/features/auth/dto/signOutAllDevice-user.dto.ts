import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class SignOutAllDeviceUserDto {
  @ApiProperty()
  @IsUUID()
  userId: string;
}
