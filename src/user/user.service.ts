import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
    constructor(private prismaService: PrismaService){}

    async createUser(userDTO: Omit<User, "id"|"refreshToken"|"otpCode"|"otpCreatedAt"|"isAdmin">):Promise<User>{
        let user = await this.prismaService.Client.user.findUnique({where: {email: userDTO.email}})
        if(user){
            return null;
        }
        user = await this.prismaService.Client.user.create({data: {...userDTO}})
        return user;
    }

    async getUserByEmail(email: string):Promise<User>{
        let user = await this.prismaService.Client.user.findUnique({where: {email: email}})
        if(!user){
            return null;
        }
        return user;
    }

    async getUserById(id: number):Promise<User>{
        let user = await this.prismaService.Client.user.findUnique({where: {id: id}})
        if(!user){
            return null;
        }
        return user;
    }

    async storeRefreshToken(token: string, userId: number):Promise<User>{
        return await this.prismaService.Client.user.update({where: {id: userId}, data: {refreshToken: token}})
    }

    async verifyUser(userId: number):Promise<User>{
        return await this.prismaService.Client.user.update({where: {id: userId}, data: {verified: true}})
    }

    async storeOTP(code: string, userId: number):Promise<User>{
        return await this.prismaService.Client.user.update({where: {id: userId}, data: {otpCode: code, otpCreatedAt: new Date()}})
    }

    async resetUserOTP(userId: number):Promise<User>{
        return await this.prismaService.Client.user.update({where: {id: userId}, data:{otpCode: ""}})
    }
}
