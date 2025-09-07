import { createParamDecorator, ExecutionContext } from '@nestjs/common';


/**
* Usage:
* me(@CurrentUser() user) -> full user object
* me(@CurrentUser('email') email) -> single field
*/
export const CurrentUser = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();
    if (!req) return null;
    if (typeof data === 'string') return req.user?.[data];
    return req.user ?? null;
});