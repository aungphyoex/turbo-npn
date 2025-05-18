import { User } from '@/features/users/entities/user.entity';
import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly UserRepository: Repository<User>,
  ) {}
  async findAll(): Promise<User[]> {
    return await this.UserRepository.find();
  }

  /**
   * @description Get user by username
   * @param identifier
   * @return Promise<User>
   */
  async findOne(identifier: string): Promise<User> {
    const user = await this.UserRepository.findOne({
      where: { username: identifier },
    });
    if (!user) {
      throw new NotFoundException('User not found.');
    }
    return user;
  }
}
