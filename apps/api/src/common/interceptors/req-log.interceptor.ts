import { concatStr } from '@/common/utils';
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class ReqLogInterceptor implements NestInterceptor {
  private readonly logger: Logger;
  constructor() {
    this.logger = new Logger('REQUEST INTERCEPTOR', { timestamp: true });
  }
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();
    /* *
     * Before the request is handled, log the request details
     * */
    this.logger.log(concatStr([req.method, req.originalUrl]));
    return next.handle().pipe(
      tap(() =>
        /* *
         * After the request is handled, log the response details
         * */
        this.logger.log(
          concatStr([req.method, req.originalUrl, res.statusCode]),
        ),
      ),
    );
  }
}
