import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppService } from 'src/app.service';
import { UserModule } from 'src/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { BcryptModule } from 'src/bcrypt/bcrypt.module';

@Module({
  controllers: [AuthController],
  providers: [AuthService, AppService],
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        global: true,
        secret: configService.get<string>('JWT_SECRET'),
      }),
    }),
    UserModule,
    BcryptModule,
    ConfigModule
  ],
})
export class AuthModule {}
