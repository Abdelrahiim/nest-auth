import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyCookie from '@fastify/cookie';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  );
  app.useGlobalPipes(new ValidationPipe());
  app.register(fastifyCookie, {
    secret:
      '681ef47db0419b359b9f7ce0762a900a75db524f587b0642df7578a79ed5ac352d2ff1316e2c2f5a6bd6ccb6a4ba2bddb6224c7f4797e042a531aaf3da51cf7e',
  });
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
