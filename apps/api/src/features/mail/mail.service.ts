import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendEmail(mailOptions: ISendMailOptions): Promise<void> {
    await this.mailerService.sendMail(mailOptions);
  }
}
