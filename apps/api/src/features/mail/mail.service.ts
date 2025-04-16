import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly config: ConfigService,
  ) {}

  async sendEmail(mailOptions: ISendMailOptions): Promise<void> {
    await this.mailerService.sendMail({
      from: `♻️ Turborepo ⚡ <${this.config.get('MAIL_USERNAME')}>`,
      ...mailOptions,
    });
  }
}
