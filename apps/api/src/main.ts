import { AppModule } from '@/app.module';
import { bootstrap } from '@/bootstrap';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';

/**
 * Main entry point to bootstrap the NestJS Fastify application.
 *
 * @returns {Promise<void>} A promise that resolves when the application has started.
 */
const main = async (): Promise<void> => {
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
 * Invokes the main bootstrap function and handles any errors.
 *
 * @returns {void}
 */
main().catch((error) => {
  console.log(error);
  process.exit(1);
});
