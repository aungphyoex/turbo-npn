import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty()
  @IsString({
    message: 'Refresh token must be a string',
  })
  refresh_token: string;

  @ApiProperty()
  @IsString({
    message: 'User Id must be a string',
  })
  user_id: string;
}
