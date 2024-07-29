import { Module } from '@nestjs/common';
import { BcryptService } from './bcrypt.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  providers: [BcryptService],
  exports: [BcryptService],
  imports: [ConfigModule]
})
export class BcryptModule {}
