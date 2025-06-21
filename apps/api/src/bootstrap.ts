import { Env } from '@/common/utils';
import { swagger } from '@/swagger';
import helmet from '@fastify/helmet';
import fastifyMultipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { Logger, LoggerErrorInterceptor } from 'nestjs-pino';
import { join } from 'path';

/**
 * Initializes the NestJS application with Fastify, configuring middleware, security, validation,
 * CORS, static assets, logging, and API documentation.
 *
 * @param {NestFastifyApplication} app - The NestFastifyApplication instance.
 * @returns {Promise<void>} Resolves when the application has started.
 */
export const bootstrap = async (app: NestFastifyApplication): Promise<void> => {
  // Logger instance for logging application events
  const logger = app.get(Logger);

  // Configuration service to get environment variables and other settings
  const configService = app.get(ConfigService<Env>);

  // Set up security headers using helmet (Fastify plugin)
  await app.register(helmet, {
    global: true,
    permittedCrossDomainPolicies: false,
  });

  // Serve static assets using Fastify's static plugin
  await app.register(fastifyStatic, {
    root: join(__dirname, '..', 'storage', 'public'),
    prefix: '/assets/',
    decorateReply: false,
    dotfiles: 'deny',
  });

  // Enable CORS with allowed origins and methods
  app.enableCors({
    credentials: true,
    origin: configService.get('ALLOW_CORS_URL').split(','),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  });

  // Use custom logger for application logs
  app.useLogger(logger);

  // Global validation pipe for request validation
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

  // Swagger setup to enable API documentation in non-production environments
  if (configService.get('NODE_ENV') !== 'production') {
    await swagger(app);
  }

  // Global error logging interceptor
  app.useGlobalInterceptors(new LoggerErrorInterceptor());

  // Register Fastify multipart plugin for file uploads
  await app.register(fastifyMultipart);

  // Start the application and listen on the configured port and host
  await app.listen(configService.get('PORT')!, '0.0.0.0', () => {
    logger.log(
      `This application started at ${configService.get('HOST')}:${configService.get('PORT')}`,
    );
  });
};
