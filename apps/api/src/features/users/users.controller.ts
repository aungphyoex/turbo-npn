import { Controller, Get } from '@nestjs/common';
import { UsersService } from './users.service';
import { ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }


  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({ status: 200, description: 'Users fetched successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiBearerAuth()
  @Get()
  async findAll() {
    const data = await this.usersService.findAll();
    return { message: 'Users fetched successfully', data };
  }


}
