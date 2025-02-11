import { Env } from '@/common/utils';
import { swagger } from '@/swagger';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';

export const bootstrap = async (app: NestExpressApplication) => {
  const logger = app.get(Logger);
  const configService = app.get(ConfigService<Env>);

  app.useStaticAssets('./uploads', {
    prefix: '/assets',
  });
  app.enableCors({
    credentials: true,
    origin: configService.get('ALLOW_CORS_URL'),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  });
  app.useLogger(logger);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  await swagger(app);
  await app.listen(configService.get('PORT')!, () => {
    logger.log(
      `This application started at ${configService.get('HOST')}:${configService.get('PORT')}`,
    );
  });
};
