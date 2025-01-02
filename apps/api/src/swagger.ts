import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export const swagger = async (app: NestExpressApplication) => {
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Turbo repo')
    .setVersion('0.0.0.1')
    .setDescription('Turbo repo api with nestjs.')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api-docs', app, document);
};
