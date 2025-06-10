import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class DeleteUserDto {
  @ApiProperty()
  @IsString()
  user_id: string;

  @ApiProperty()
  @IsString()
  password: string;
}
