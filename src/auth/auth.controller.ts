import { BadRequestException, Body, Controller, ForbiddenException, Get, InternalServerErrorException, NotFoundException, Post, Req, UnauthorizedException, UploadedFile, UseGuards, UseInterceptors } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { BcryptService } from 'src/bcrypt/bcrypt.service';
import { UserService } from 'src/user/user.service';
import { AuthService } from './auth.service';
import { AppService } from 'src/app.service';
import { User } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AdminGuard } from 'src/admin/admin.guard';
// import { UserGuard } from 'src/user/user.guard';
// import { AdminGuard } from 'src/admin/admin.guard';
// import { FileInterceptor } from '@nestjs/platform-express';
// import { diskStorage } from 'multer';
// import { extname } from 'path';

@Controller('auth')
export class AuthController {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
        private bcryptService: BcryptService,
        private authService: AuthService,
        private appService: AppService,
        private configService: ConfigService
    ){}
    @Post("login")
    async userLoginController(@Body() userCreds: Record<string, string>){
        let user = await this.userService.getUserByEmail(userCreds.email);
        if(!user){
            throw new UnauthorizedException("Wrong Email or Password");
        }
        if(!user.verified){
            throw new UnauthorizedException("User Not Verified..");
        }
        const validPassword = await this.bcryptService.compareSync(userCreds.password, user.password);
        if(!validPassword){
            throw new UnauthorizedException("Wrong Email or Password");
        }
        let otp = this.authService.generateOTP();
        await this.userService.storeOTP(await this.bcryptService.hashSync(otp), user.id);
        const mailMessage = `
        Welcome Back ${user.name}!
        You've attempted to login into your account.
        Your confirmation code is ${otp}
        Your code will expire in 5 minutes
        If you think you received this account by mistake please contact us.
        Don't share this mail with anyone.
        `
        this.appService.sendMail(user.email, mailMessage, 'Welcome Back!')
        delete user.password
        delete user.refreshToken
        delete user.otpCode
        delete user.otpCreatedAt
        return {message: "Confirmation Code Sent..", user}
    }

    @Post("signup")
    async signupUserController(@Body() userDTO: Omit<User, "id"|"refreshToken">){
        userDTO.password = await this.bcryptService.hashSync(userDTO.password)
        const otp = this.authService.generateOTP();
        userDTO.otpCode = await this.bcryptService.hashSync(otp);
        userDTO.otpCreatedAt = new Date();
        userDTO.verified = false;
        userDTO.isAdmin = false;
        let user = await this.userService.createUser(userDTO);
        if(!user){
            throw new InternalServerErrorException("Something Went Wrong..")
        }
        const mailMessage = `
        Welcome On Board ${user.name}!
        You're a few steps away from Creating Your Account!
        Your confirmation code is ${otp}
        Your code will expire in 5 minutes
        If you think you received this account by mistake please contact us.
        Don't share this mail with anyone.
        `
        this.appService.sendMail(user.email, mailMessage, "Welcome On Board!")
        return {user};
    }

    @Post("verify")
    async verifyUserController(@Body() userCreds: Record<string, string>){
        let user = await this.userService.getUserByEmail(userCreds.email);
        if(!user){
            throw new NotFoundException("User Not Found..");
        }
        if(!user.otpCode || !user.otpCreatedAt){
            throw new BadRequestException("No OTP Exist..");
        }
        const expire = user.otpCreatedAt;
        expire.setMinutes(expire.getMinutes() + 5);
        const now = new Date();
        if(now > expire){
            this.userService.resetUserOTP(user.id);
            throw new UnauthorizedException("OTP Expired..")
        }
        const validCode = await this.bcryptService.compareSync(userCreds.otp, user.otpCode);
        if(!validCode){
            throw new UnauthorizedException("Wrong OTP..")
        }
        this.userService.resetUserOTP(user.id);
        if(!user.verified){
            user = await this.userService.verifyUser(user.id);
            const mailMessage = `
            Welcome On Board ${user.name}!
            You're all set!
            If you think you received this account by mistake please contact us.
            `
            this.appService.sendMail(user.email, mailMessage, 'Account Activated')
        }
        const accessPayload = await this.bcryptService.encryptPayload({
            id: user.id,
            email: user.email
        })
        const refreshPayload = await this.bcryptService.encryptPayload({
            id: user.id,
            email: user.email,
            isRef: true
        })
        let refreshToken = await this.jwtService.signAsync({refreshPayload}, {expiresIn: "30d"})
        const accessToken = await this.jwtService.signAsync({accessPayload}, {expiresIn: "5m"})
        this.userService.storeRefreshToken(await this.bcryptService.hashSync(refreshToken), user.id);
        delete user.password
        delete user.refreshToken
        delete user.otpCode
        delete user.otpCreatedAt

        return {user, refreshToken, accessToken}
    }

    @Post("/admin/verify")
    async verifyAdminController(@Body() userCreds: Record<string, string>){
        let user = await this.userService.getUserByEmail(userCreds.email);
        if(!user){
            throw new NotFoundException("User Not Found..");
        }
        if(!user.isAdmin){
            throw new ForbiddenException();
        }
        if(!user.otpCode || !user.otpCreatedAt){
            throw new BadRequestException("No OTP Exist..");
        }
        const expire = user.otpCreatedAt;
        expire.setMinutes(expire.getMinutes() + 5);
        const now = new Date();
        if(now > expire){
            this.userService.resetUserOTP(user.id);
            throw new UnauthorizedException("OTP Expired..")
        }
        const validCode = await this.bcryptService.compareSync(userCreds.otp, user.otpCode);
        if(!validCode){
            throw new UnauthorizedException("Wrong OTP..")
        }
        this.userService.resetUserOTP(user.id);
        if(!user.verified){
            user = await this.userService.verifyUser(user.id);
            const mailMessage = `
            Welcome On Board ${user.name}!
            You're all set!
            If you think you received this account by mistake please contact us.
            `
            this.appService.sendMail(user.email, mailMessage, 'Account Activated')
        }
        const accessPayload = await this.bcryptService.encryptPayload({
            id: user.id,
            email: user.email
        })
        const refreshPayload = await this.bcryptService.encryptPayload({
            id: user.id,
            email: user.email,
            isRef: true
        })
        let refreshToken = await this.jwtService.signAsync({refreshPayload}, {secret: this.configService.get("JWT_ADMIN_SECRET"), expiresIn: "30d"})
        const accessToken = await this.jwtService.signAsync({accessPayload}, {secret: this.configService.get("JWT_ADMIN_SECRET"), expiresIn: "5m"})
        this.userService.storeRefreshToken(await this.bcryptService.hashSync(refreshToken), user.id);
        delete user.password
        delete user.refreshToken
        delete user.otpCode
        delete user.otpCreatedAt

        return {user, refreshToken, accessToken}
    }

    @Post("/admin/refresh")
    async adminRefreshTokenController(@Req() req: any){
        if(!req.header("Authorization")){
            throw new UnauthorizedException();
        }
        const refreshToken = req.header("Authorization").split(" ")[1];
        const decoded = await this.jwtService.verifyAsync(refreshToken, {secret: this.configService.get<string>("JWT_ADMIN_SECRET")});
        const decrypted = await this.bcryptService.decryptSync(decoded.refreshPayload);
        const user = await this.userService.getUserById(decrypted.id);
        if(!user){
            throw new UnauthorizedException();
        }
        const newHashValue = await this.bcryptService.hashSync(refreshToken);
        if(user.refreshToken != newHashValue){
            throw new UnauthorizedException();
        }
        let payload = {id: user.id, email: user.email};
        const accessPayload = await this.bcryptService.encryptPayload(payload);
        const accessToken = await this.jwtService.signAsync({accessPayload}, {secret: this.configService.get<string>('JWT_ADMIN_SECRET'), expiresIn: "5m"})
        return {accessToken};
    }

    @Post("/user/refresh")
    async userRefreshTokenController(@Req() req: any){
        if(!req.header("Authorization")){
            throw new UnauthorizedException(1);
        }
        const refreshToken = req.header("Authorization").split(" ")[1];
        const decoded = await this.jwtService.verifyAsync(refreshToken, {secret: this.configService.get<string>("JWT_SECRET")});
        const decrypted = await this.bcryptService.decryptSync(decoded.refreshPayload);
        const user = await this.userService.getUserById(decrypted.id);
        if(!user){
            throw new UnauthorizedException(2);
        }
        const newHashValue = await this.bcryptService.hashSync(refreshToken);
        if(user.refreshToken != newHashValue){
            throw new UnauthorizedException(3);
        }
        let payload = {id: user.id, email: user.email};
        const accessPayload = await this.bcryptService.encryptPayload(payload);
        const accessToken = await this.jwtService.signAsync({accessPayload}, {secret: this.configService.get<string>('JWT_SECRET'), expiresIn: "5m"})
        return {accessToken};
    }

    /* FILE UPLOAD TEST */
    // @Post("upload")
    // @UseInterceptors(
    //     FileInterceptor('image', {
    //     storage: diskStorage({
    //         destination: './uploads',
    //         filename: (req, file, cb) => {
    //         const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    //         const ext = extname(file.originalname);
    //         const filename = `${file.fieldname}-${uniqueSuffix}${ext}`;
    //         cb(null, filename);
    //         },
    //     }),
    //     }),
    // )
    // async testUpload(@UploadedFile() file){
    //     return { filename: file.filename };
    // }


    /* ENCRYPTION/DECRYPTION TEST */
    // @Post("en")
    // async en(@Body() data: any){
    //     return this.bcryptService.encryptPayload(data);
    // }

    // @Post("de")
    // async de(@Body() data: any){
    //     return this.bcryptService.decryptSync(data.data);
    // }


    /* USER/ADMIN GUARD TEST */
    // @Get("us")
    // @UseGuards(UserGuard)
    // async protectedUser(){
    //     return {message:"hello world"};
    // }
    
    // @Get("ad")
    // @UseGuards(AdminGuard)
    // async protectedAdmin(){
    //     return {message:"hello world"};
    // }
}
