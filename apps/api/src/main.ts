import { AppModule } from '@/app.module';
import { bootstrap } from '@/bootstrap';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';

/**
 * @description Bootstrap the application
 * @returns Promise<void>
 */
const main = async () => {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bufferLogs: true,
  });
  app.flushLogs();
  await bootstrap(app);
};

/**
 * @description Bootstrap the application
 */
main().catch((error) => {
  console.log(error);
  process.exit(1);
});
