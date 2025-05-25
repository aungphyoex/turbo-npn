import { Module } from '@nestjs/common';
import { APP_NAME } from '@repo/constants/app';
import { LoggerModule as PinoLoggerModule } from 'nestjs-pino';

@Module({
  imports: [
    PinoLoggerModule.forRootAsync({
      useFactory: () => {
        return {
          forRoutes: ['*'],
          pinoHttp: {
            quietReqLogger: true,
            quietResLogger: true,
            name: APP_NAME,
            autoLogging: true,
            transport: {
              target: 'pino-pretty',
            },
          },
        };
      },
    }),
  ],
})
export class LoggerModule {}
