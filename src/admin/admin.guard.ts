import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { BcryptService } from 'src/bcrypt/bcrypt.service';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(private jwtService: JwtService, private bcryptService: BcryptService, private userService: UserService, private configService: ConfigService){}
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    if(!request.headers.authorization){
      throw new UnauthorizedException();
    }
    const [key, token] = request.headers.authorization?.split(' ');
    if (!key || !token) {
      throw new UnauthorizedException();
    }
    try {
      const decoded = await this.jwtService.verifyAsync(token, {secret: this.configService.get<string>("JWT_ADMIN_SECRET")});
      const decrypted = await this.bcryptService.decryptSync(decoded.accessPayload)
      const user = await this.userService.getUserById(decrypted.id);
      if(!user){
        throw new UnauthorizedException();
      }
      if(!user.isAdmin){
        throw new ForbiddenException();
      }
      request.user = decrypted;
      return true
    } catch (error) {
      throw new ForbiddenException();
    }
  }
}
