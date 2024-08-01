import { Injectable } from '@nestjs/common';
import { Product } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class ProductService {
    constructor(private prismaService: PrismaService){}

    async createProduct(productDTO: Omit<Product, "id" | "userId" | "createdAt" | "updatedAt">):Promise<Product>{
        const product = await this.prismaService.Client.product.create({data: productDTO});
        return product;
    }
    async getProducts():Promise<Product[]>{
        return await this.prismaService.Client.product.findMany();
    }
    async getProduct(id: number):Promise<Product>{
        const product = await this.prismaService.Client.product.findUnique({where: {id: id}});
        if(!product){
            return null;
        }
        return product;
    }
}
