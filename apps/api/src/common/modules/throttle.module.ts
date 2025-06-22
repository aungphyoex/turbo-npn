import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';

/**
 * Module for configuring API rate limiting using NestJS Throttler.
 *
 * Defines multiple throttler strategies (short, medium, long) with different
 * time-to-live (ttl) and request limits. Provides a custom error message
 * when rate limits are exceeded.
 */
@Module({
  imports: [
    ThrottlerModule.forRoot({
      throttlers: [
        {
          name: 'short',
          ttl: 1000, // 1 second
          limit: 100,
        },
        {
          name: 'medium',
          ttl: 10000, // 10 seconds
          limit: 200,
        },
        {
          name: 'long',
          ttl: 60000, // 1 minute
          limit: 300,
        },
      ],
      errorMessage: 'Too many requests, please try again later.',
    }),
  ],
})
export class ThrottleModule {}
