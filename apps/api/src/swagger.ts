import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

/**
 * Sets up Swagger API documentation for the application.
 *
 * @param {NestFastifyApplication} app - The NestJS Fastify application instance.
 * @returns {Promise<void>} A promise that resolves when Swagger is set up.
 */
export const swagger = async (app: NestFastifyApplication): Promise<void> => {
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Turbo repo')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api-docs', app, document);
};
