import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';
import { PrismaService } from 'prisma/prisma.service';


/**
* SessionMiddleware: resolves the session token from cookie -> loads session -> loads user -> attaches req.user
* - Safe: omits sensitive fields (passwordHash)
* - Swallows transient DB errors (does not block public routes)
*/
@Injectable()
export class SessionMiddleware implements NestMiddleware {
    private readonly logger = new Logger(SessionMiddleware.name);


    constructor(private prisma: PrismaService, private auth: AuthService) { }


    async use(req: Request & { user?: any; session?: any }, _res: Response, next: NextFunction) {
        try {
            const cookieName = process.env.COOKIE_NAME || 'sid';
            const token = req.cookies?.[cookieName];
            if (!token) return next();


            const session = await this.auth.getSessionByToken(token);
            if (!session) return next();
            if (session.revokedAt) return next();
            if (session.expiresAt < new Date()) return next();


            // Rolling expiry (configurable in env SESSION_ROLLING)
            await this.auth.touchSession(token).catch((err) => this.logger.debug('touchSession failed', err));


            const user = await this.prisma.user.findUnique({ where: { id: session.userId } });
            if (!user) return next();


            // Attach safe user object
            req.user = { id: user.id, email: user.email, name: user.name };
            req.session = { id: session.id, token: session.token, expiresAt: session.expiresAt };
        } catch (err) {
            // Log, but do not block execution of public routes
            this.logger.debug('Session middleware error', err as any);
        }


        return next();
    }
}