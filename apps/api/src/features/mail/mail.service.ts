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
    const { from, ...options } = mailOptions;
    await this.mailerService.sendMail({
      from: `Turbo NPN <${this.config.get('MAIL_USERNAME')}>`,
      ...options,
    });
  }
}
