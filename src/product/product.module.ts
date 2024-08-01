import { Module } from '@nestjs/common';
import { ProductController } from './product.controller';
import { ProductService } from './product.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { BcryptModule } from 'src/bcrypt/bcrypt.module';
import { UserService } from 'src/user/user.service';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from 'src/user/user.module';

@Module({
  controllers: [ProductController],
  providers: [ProductService],
  imports: [PrismaModule, JwtModule, BcryptModule, UserModule, ConfigModule]
})
export class ProductModule {}
