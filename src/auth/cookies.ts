import { Response } from 'express';


export function setSessionCookie(res: Response, token: string) {
    const name = process.env.COOKIE_NAME || 'sid';
    const maxAge = (parseInt(process.env.SESSION_TTL_SECONDS || '1209600', 10)) * 1000;
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie(name, token, {
        httpOnly: true,
        secure: isProd, // set true behind HTTPS
        sameSite: 'lax',
        domain: process.env.COOKIE_DOMAIN || undefined,
        path: '/',
        maxAge,
    });
}


export function clearSessionCookie(res: Response) {
    const name = process.env.COOKIE_NAME || 'sid';
    const isProd = process.env.NODE_ENV === 'production';
    res.clearCookie(name, { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' });
}