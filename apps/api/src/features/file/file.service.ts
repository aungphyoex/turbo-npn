import { Env } from '@/common/utils';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FileService {
  constructor(private readonly configService: ConfigService<Env>) {}
  uploadFiles(files: File[]) {}

  deleteFiles() {}

  uploadFile(file: File) {}

  deleteFile() {}

  createFolder() {}

  deleteFolder() {}
}
