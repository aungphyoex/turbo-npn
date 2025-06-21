import { Public } from '@/common/decorators';
import { FileService } from '@/features/file/file.service';
import {
  FileInterceptor,
  MemoryStorageFile,
  UploadedFile,
} from '@blazity/nest-file-fastify';
import { Controller, Get, Param, Post, UseInterceptors } from '@nestjs/common';
import { UsersService } from './users.service';

/**
 * Controller for managing user-related operations.
 *
 * Provides endpoints to fetch all users, fetch a single user by identifier,
 * and test file upload functionality.
 */
@Controller('users')
export class UsersController {
  /**
   * Creates an instance of UsersController.
   *
   * @param {UsersService} usersService - Service for user-related operations.
   * @param {FileService} fileService - Service for file-related operations.
   */
  constructor(
    private readonly usersService: UsersService,
    private readonly fileService: FileService,
  ) {}

  /**
   * Fetches all users.
   *
   * @returns {Promise<{ message: string; data: any[] }>} An object containing a message and an array of user data without passwords.
   */
  @Public()
  @Get()
  async findAll(): Promise<{ message: string; data: any[] }> {
    const users = await this.usersService.findAll();
    const data = users.map(({ password, ...user }) => ({
      ...user,
    }));
    return { message: 'Users fetched successfully', data };
  }

  /**
   * Fetches a single user by identifier.
   *
   * @param {string} identifier - The identifier of the user (e.g., ID or username).
   * @returns {Promise<{ message: string; data: any }>} An object containing a message and the user data without password.
   */
  @Public()
  @Get(':identifier')
  async findOne(
    @Param('identifier') identifier: string,
  ): Promise<{ message: string; data: any }> {
    const user = await this.usersService.findOne(identifier);
    const { password, ...data } = user;
    return { message: 'User fetched successfully', data };
  }

  /**
   * Endpoint for testing file upload.
   *
   * @param {MemoryStorageFile} file - The uploaded file.
   */
  @Public()
  @Post()
  @UseInterceptors(FileInterceptor('file'))
  async fileTesting(
    @UploadedFile()
    file: MemoryStorageFile,
  ) {
    const upFile = await this.fileService.uploadFile(file);
    return upFile;
  }
}
