import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
    @ApiProperty({
        description: 'Current password',
    })
    @IsString()
    @IsNotEmpty()
    currentPassword: string;

    @ApiProperty({
        description: 'New password',
        minimum: 8,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    newPassword: string;

    @ApiProperty({
        description: 'Confirm new password',
        minimum: 8,
    })
    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    confirmNewPassword: string;

    user_id: string;
} 