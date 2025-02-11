import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class SignOutUserDto {
  @ApiProperty()
  @IsString({
    message: 'User Id must be a string',
  })
  user_id: string;
}
