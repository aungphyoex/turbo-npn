import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
    @ApiProperty({
        description: 'Reset token received in email',
    })
    @IsString()
    @IsNotEmpty()
    token: string;

    @ApiProperty({
        description: 'New password',
        minimum: 8,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    password: string;

    @ApiProperty({
        description: 'Confirm new password',
        minimum: 8,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    confirmPassword: string;
} 