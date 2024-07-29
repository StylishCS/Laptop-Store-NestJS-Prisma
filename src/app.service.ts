import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AppService {
  constructor(private mailerService: MailerService) {}
  getHello(): string {
    return 'Hello World!';
  }
  async sendMail(to: string, message: string, subject: string){
    await this.mailerService.sendMail({
      from: "Osta Abdo El Balf",
      to: to,
      subject: subject,
      text: message,
    })
  }
}
