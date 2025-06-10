import { Env } from '@/common/utils';
import { swagger } from '@/swagger';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import helmet from 'helmet';
import { Logger, LoggerErrorInterceptor } from 'nestjs-pino';
import { join } from 'path';

/**
 * This function initializes the NestJS application with various middlewares, settings, and configurations.
 * It is used to set up global configurations for security, validation, logging, CORS, and more.
 *
 * @param app The NestExpressApplication instance.
 *
 * @returns {Promise<void>} Resolves when the application has started.
 */
export const bootstrap = async (app: NestFastifyApplication): Promise<void> => {
  // Logger instance for logging application events
  const logger = app.get(Logger);

  // Configuration service to get environment variables and other settings
  const configService = app.get(ConfigService<Env>);

  // Set up security headers using helmet
  app.use(
    helmet({
      permittedCrossDomainPolicies: false,
    }),
  );

  // Global API prefix setup, excluding certain paths from the prefix
  // app.setGlobalPrefix('api', {
  //   exclude: [
  //     {
  //       path: '/',
  //       method: RequestMethod.GET,
  //     },
  //     {
  //       path: '/api-docs',
  //       method: RequestMethod.GET,
  //     },
  //     {
  //       path: '/health',
  //       method: RequestMethod.GET,
  //     },
  //   ],
  // });

  // Static asset handling (for storage)
  // For express nest application
  app.useStaticAssets({
    dotfiles: 'deny',
    prefix: '/assets/',
    root: join(__dirname, '..', 'storage'),
    serve: true,
  });
  // CORS setup allowing specific origins and methods
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
      whitelist: true, // Only allows properties defined in DTOs
      forbidNonWhitelisted: true, // Rejects any extra properties in the request
      transform: true, // Transforms payloads to DTO types
      transformOptions: {
        enableImplicitConversion: true, // Enable implicit conversion of types
      },
    }),
  );

  // Swagger setup to enable API documentation
  if (configService.get('NODE_ENV') !== 'production') {
    await swagger(app);
  }

  // Nestjs pino error logger interceptor
  app.useGlobalInterceptors(new LoggerErrorInterceptor());

  // Start the application
  await app.listen(configService.get('PORT')!, () => {
    logger.log(
      `This application started at ${configService.get('HOST')}:${configService.get('PORT')}`,
    );
  });
};
