import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { PrismaService } from 'prisma/prisma.service';


function nowPlus(seconds: number) {
    const d = new Date();
    d.setSeconds(d.getSeconds() + seconds);
    return d;
}

@Injectable()
export class AuthService { 

    private ttl = parseInt(process.env.SESSION_TTL_SECONDS || '1209600', 10); // 14d default


    constructor(private users: UsersService, private prisma: PrismaService) { }

    async register(email: string, password: string, name?: string) {
        const existing = await this.users.findByEmail(email);
        if (existing) throw new BadRequestException('Email already in use');


        const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
        const user = await this.users.create(email, passwordHash, name);
        return user;
    }


    async validateUser(email: string, password: string) {
        const user = await this.users.findByEmail(email);
        if (!user) throw new UnauthorizedException('Invalid credentials');
        const ok = await argon2.verify(user.passwordHash, password);
        if (!ok) throw new UnauthorizedException('Invalid credentials');
        return user;
    }


    async createSession(userId: string, ip?: string, userAgent?: string) {
        const token = randomBytes(32).toString('hex');
        return this.prisma.session.create({
            data: {
                token,
                userId,
                ip,
                userAgent,
                expiresAt: nowPlus(this.ttl),
            },
        });
    }


    async getSessionByToken(token: string) {
        return this.prisma.session.findUnique({ where: { token } });
    }


    async touchSession(token: string) {
        const rolling = (process.env.SESSION_ROLLING || 'true') === 'true';
        if (!rolling) return;
        await this.prisma.session.update({
            where: { token },
            data: { expiresAt: nowPlus(this.ttl) },
        });
    }


    async revokeSession(token: string) {
        await this.prisma.session.update({ where: { token }, data: { revokedAt: new Date() } });
    }


    async revokeAllSessionsForUser(userId: string) {
        await this.prisma.session.updateMany({
            where: { userId, revokedAt: null },
            data: { revokedAt: new Date() },
        });
    }

}