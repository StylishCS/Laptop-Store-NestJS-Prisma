import { Body, Controller, Get, InternalServerErrorException, NotFoundException, Param, Post, UploadedFile, UseGuards, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { ProductService } from './product.service';
import { Product } from '@prisma/client';
import { AdminGuard } from 'src/admin/admin.guard';

@Controller('product')
export class ProductController {
    constructor(private productService: ProductService){}
    @Post()
    @UseGuards(AdminGuard)
    @UseInterceptors(
        FileInterceptor('image', {
        storage: diskStorage({
            destination: './uploads',
            filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
            const ext = extname(file.originalname);
            const filename = `${file.fieldname}-${uniqueSuffix}${ext}`;
            cb(null, filename);
            },
        }),
        }),
    )
    async createProductController(@Body() productDTO: Omit<Product, "id"|"createdAt"|"updatedAt"|"userId">, @UploadedFile() file:any){
        productDTO.image = `http://localhost:3000/uploads/${file.filename}`
        productDTO.price = +productDTO.price;
        const product = await this.productService.createProduct(productDTO);
        if(!product){
            throw new InternalServerErrorException("Something Went Wrong");
        }
        return {product}
    }

    @Get()
    async getProductsController(){
        const products = await this.productService.getProducts();
        return {products};
    }

    @Get(":id")
    async getProductByIdController(@Param("id") productId:number){  
        const product = await this.productService.getProduct(+productId);
        if(!product){
            throw new NotFoundException();
        }
        return {product}
    }
}
