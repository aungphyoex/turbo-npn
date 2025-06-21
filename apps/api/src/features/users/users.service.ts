import { User } from '@/features/users/entities/user.entity';
import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

/**
 * Service for managing user data.
 */
@Injectable()
export class UsersService {
  /**
   * Creates an instance of UsersService.
   *
   * @param {Repository<User>} UserRepository - Repository for user entities.
   */
  constructor(
    @InjectRepository(User) private readonly UserRepository: Repository<User>,
  ) {}

  /**
   * Retrieves all users with their profiles.
   *
   * @returns {Promise<User[]>} A promise that resolves to an array of users with profiles.
   */
  async findAll(): Promise<User[]> {
    return await this.UserRepository.find({
      relations: ['profile'],
    });
  }

  /**
   * Gets a user by username.
   *
   * @param {string} identifier - The username of the user to find.
   * @returns {Promise<User>} A promise that resolves to the user entity.
   * @throws {NotFoundException} If the user is not found.
   */
  async findOne(identifier: string): Promise<User> {
    const user = await this.UserRepository.findOne({
      where: { username: identifier },
      relations: ['profile'],
    });
    if (!user) {
      throw new NotFoundException('User not found.');
    }
    return user;
  }
}
