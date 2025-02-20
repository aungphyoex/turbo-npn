import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty()
  @IsString({
    message: 'Identifier must be a string',
  })
  identifier: string;
}
