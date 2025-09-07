import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';


@Injectable()
export class SessionGuard implements CanActivate {
    constructor(private auth: AuthService) { }


    async canActivate(ctx: ExecutionContext): Promise<boolean> {
        const request = ctx.switchToHttp().getRequest();
        const token = request.cookies?.[process.env.COOKIE_NAME || 'sid'];
        if (!token) throw new UnauthorizedException('No session');


        const session = await this.auth.getSessionByToken(token);
        if (!session || session.revokedAt) throw new UnauthorizedException('Invalid session');


        if (session.expiresAt < new Date()) throw new UnauthorizedException('Session expired');


        // rolling expiry
        await this.auth.touchSession(token);


        // attach user to request
        request.user = await request.app.get('PrismaService').user.findUnique({ where: { id: session.userId } });
        request.session = session;
        return true;
    }
}