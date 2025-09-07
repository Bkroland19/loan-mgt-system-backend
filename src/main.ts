import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);


  app.use(helmet());
  app.use(cookieParser());
  app.enableCors({
    origin: true, // in prod, set explicit origins
    credentials: true,
  });


  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));


  await app.listen(process.env.PORT || 3000);
}
bootstrap();