import { IsEqualTo } from '@/common/decorators/is-equal-to.decorator';
import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString({
    message: 'Password must be a string',
  })
  @IsStrongPassword({
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })
  password: string;

  @IsEqualTo('password')
  confirmPassword: string;

  @IsString({
    message: 'Username must be a string',
  })
  username: string;

  @IsString({
    message: 'Name must be a string',
  })
  name: string;
}
