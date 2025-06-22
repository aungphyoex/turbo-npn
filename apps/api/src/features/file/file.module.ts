import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { FileService } from './file.service';

@Module({
  imports: [LoggerModule, ConfigModule],
  exports: [FileService],
  providers: [FileService],
})
export class FileModule {}
