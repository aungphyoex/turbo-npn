import { MailerModule } from '@nestjs-modules/mailer';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MailService } from './mail.service';

@Module({
  imports: [MailerModule, ConfigModule],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
