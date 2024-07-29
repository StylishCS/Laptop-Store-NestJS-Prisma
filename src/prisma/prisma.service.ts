import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService {
    public Client: PrismaClient

    constructor() {
        this.Client = new PrismaClient();
    }
}
