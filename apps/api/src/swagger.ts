import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export const swagger = async (app: NestFastifyApplication) => {
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Turbo repo')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api-docs', app, document);
};
