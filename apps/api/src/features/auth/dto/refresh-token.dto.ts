import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty()
  @IsString({
    message: 'User Id must be a string',
  })
  user_id: string;

  @ApiProperty()
  @IsString({
    message: 'Session token must be a string',
  })
  session_token: string;
}
