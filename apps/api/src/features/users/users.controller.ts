import { Public } from '@/common/decorators';
import { Controller, Get } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Public()
  @Get()
  async findAll() {
    const users = await this.usersService.findAll();
    const data = users.map(({ password, ...user }) => ({
      ...user,
    }));
    return { message: 'Users fetched successfully', data };
  }
}
