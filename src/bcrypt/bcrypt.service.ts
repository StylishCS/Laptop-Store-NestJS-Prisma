import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class BcryptService {
  constructor(private configService: ConfigService) {}

  async hashSync(value: string) {
    return crypto.createHash('SHA256').update(value).digest('hex');
  }

  async compareSync(value: string, hash: string) {
    const newHashValue = crypto
      .createHash('SHA256')
      .update(value)
      .digest('hex');
    return hash === newHashValue;
  }

  async encryptSync(value: string): Promise<string> {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      this.configService.get('ENCRYPTION_ALGORITHM'),
      this.configService.get('ENCRYPTION_KEY'),
      iv,
    );
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
  }

  async decryptSync(value: string): Promise<any> {
    const [ivHex, encrypted] = value.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(
      this.configService.get('ENCRYPTION_ALGORITHM'),
      this.configService.get('ENCRYPTION_KEY'),
      iv,
    );
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  }

  async encryptPayload(payload: any){
    return await this.encryptSync(JSON.stringify(payload));
  }
}
