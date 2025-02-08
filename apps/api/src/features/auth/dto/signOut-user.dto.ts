import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignOutUserDto {
  @ApiProperty({
    description: 'User ID',
    example: '123e4567-e89b-12d3-a456-426614174000'
  })
  @IsString({
    message: 'User Id must be a string',
  })
  user_id: string;
}
