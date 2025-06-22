import { concatStr } from '@/common/utils';
import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { Logger } from 'nestjs-pino';

/**
 * Middleware for logging HTTP requests in a NestJS application.
 *
 * Logs the HTTP method and URL for each incoming request using the Pino logger.
 */
@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  /**
   * Creates an instance of LoggerMiddleware.
   *
   * @param {Logger} logger - The Pino logger instance injected by the NestJS DI container.
   */
  constructor(private readonly logger: Logger) {}

  /**
   * Logs the HTTP method and original URL of each incoming request.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {NextFunction} next - The next middleware function in the chain.
   * @returns {void}
   */
  use(req: Request, res: Response, next: NextFunction): void {
    this.logger.log(concatStr([req.method, req.originalUrl]), 'Request');
    next();
  }
}
