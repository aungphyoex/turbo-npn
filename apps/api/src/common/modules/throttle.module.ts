import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      throttlers: [
        {
          name: 'short',
          ttl: 1000, // 1 sec
          limit: 100,
        },
        {
          name: 'medium',
          ttl: 10000, // 10 sec
          limit: 200,
        },
        {
          name: 'long',
          ttl: 60000, // 1 min
          limit: 300,
        },
      ],
      errorMessage: 'Too many requests, please try again later.',
    }),
  ],
})
export class ThrottleModule {}
