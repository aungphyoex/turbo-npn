import { Module } from '@nestjs/common';
import { LoggerModule as PinoModule } from 'nestjs-pino';

@Module({
  imports: [
    PinoModule.forRoot({
      pinoHttp: {
        quietReqLogger: true,
        quietResLogger: true,
        transport: {
          target: 'pino-pretty',
        },
      },
    }),
  ],
})
export class LoggerModule {}
