import { Env } from '@/common/utils';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule as PinoModule } from 'nestjs-pino';

@Module({
  imports: [
    PinoModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env>) => ({
        pinoHttp: {
          quietReqLogger: true,
          quietResLogger: true,
          transport: {
            target: 'pino-pretty',
          },
        },
      }),
    }),
  ],
})
export class LoggerModule {}
