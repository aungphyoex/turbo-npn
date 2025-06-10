import { AppModule } from '@/app.module';
import { bootstrap } from '@/bootstrap';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';

/**
 * @description Bootstrap the application
 * @returns Promise<void>
 */
const main = async () => {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    {
      bufferLogs: true,
    },
  );
  await bootstrap(app);
};

/**
 * @description Bootstrap the application
 */
main().catch((error) => {
  console.log(error);
  process.exit(1);
});
