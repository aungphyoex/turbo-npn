import { concatStr } from '@/common/utils';
import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  constructor(private readonly logger: Logger) {}
  use(req: Request, res: Response, next: NextFunction) {
    this.logger.log(
      concatStr([req.method, req.originalUrl, res.statusCode]),
      'Request',
    );
    next();
  }
}
