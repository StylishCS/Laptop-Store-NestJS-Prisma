import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { BcryptModule } from 'src/bcrypt/bcrypt.module';

@Module({
  controllers: [UserController],
  providers: [UserService],
  imports: [PrismaModule, BcryptModule],
  exports: [UserService]
})
export class UserModule {}
