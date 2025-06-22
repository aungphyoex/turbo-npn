import { SaveFileOptions } from '@/common/interfaces';
import { Env, saveFileToS3 } from '@/common/utils';
import { deleteFile, deleteFiles, saveFile } from '@/common/utils/file';
import { MemoryStorageFile } from '@blazity/nest-file-fastify';
import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';

/**
 * Service for handling file operations such as upload and delete.
 */
@Injectable()
export class FileService {
  /**
   * Indicates whether the file system is public.
   * @type {boolean}
   */
  private readonly isPublic: boolean;

  /**
   * Creates an instance of FileService.
   *
   * @param {ConfigService<Env>} configService - Service for accessing environment variables.
   * @param {Logger} loggerService - Logger instance for logging errors.
   */
  constructor(
    private readonly configService: ConfigService<Env>,
    private readonly loggerService: Logger,
  ) {
    this.isPublic = this.configService.get('FILE_SYSTEM') === 'public';
  }

  /**
   * Uploads a single file to storage.
   *
   * @param {MemoryStorageFile} storageFile - The file to upload.
   * @param {SaveFileOptions} [options] - Optional file save options.
   * @returns {Promise<{ filename: string; filepath: string }>} The saved file's name and path.
   */
  async uploadFile(
    storageFile: MemoryStorageFile,
    options?: SaveFileOptions,
  ): Promise<{ filename: string; filepath: string }> {
    if (this.isPublic) {
      return await saveFile(storageFile, options);
    }
    return await saveFileToS3(storageFile, options);
  }

  /**
   * Deletes a file from storage.
   *
   * @param {string} path - The relative path of the file to delete.
   * @returns {Promise<void>}
   * @throws {BadRequestException} If deletion fails.
   */
  async deleteFile(path: string): Promise<void> {
    try {
      if (this.isPublic) {
        return await deleteFile(path);
      }
    } catch (e) {
      this.loggerService.error(e);
      throw new BadRequestException(e);
    }
  }

  /**
   * Placeholder for uploading multiple files.
   */
  async uploadFiles(): Promise<void> {}

  /**
   * Placeholder for deleting multiple files.
   */
  async deleteFiles(filePaths: string[]) {
    try {
      if (this.isPublic) {
        return await deleteFiles(filePaths);
      }
    } catch (e) {
      this.loggerService.error(e);
      throw new BadRequestException(e);
    }
  }

  /**
   * Placeholder for creating a folder.
   */
  createFolder(): void {}

  /**
   * Placeholder for deleting a folder.
   */
  deleteFolder(): void {}
}
