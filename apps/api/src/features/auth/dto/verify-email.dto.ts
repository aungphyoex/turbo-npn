import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
    @ApiProperty({
        description: 'Email verification token received in email',
    })
    @IsString()
    @IsNotEmpty()
    token: string;
} 