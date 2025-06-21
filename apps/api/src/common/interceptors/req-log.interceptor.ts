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

/**
 * Interceptor for logging HTTP request and response details.
 *
 * Logs request method and URL before handling the request.
 * Optionally logs response status after the request is handled.
 */
@Injectable()
export class ReqLogInterceptor implements NestInterceptor {
  /**
   * Logger instance for request logging.
   * @type {Logger}
   */
  private readonly logger: Logger;

  /**
   * Creates an instance of ReqLogInterceptor.
   */
  constructor() {
    this.logger = new Logger('REQUEST INTERCEPTOR', { timestamp: true });
  }

  /**
   * Intercepts incoming HTTP requests and logs details before and after handling.
   *
   * @param {ExecutionContext} context - The execution context containing request/response information.
   * @param {CallHandler} next - The handler for processing the request.
   * @returns {Observable<any>} Observable of the response stream.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    // Log request method and URL before handling
    this.logger.log(concatStr([req.method, req.originalUrl]));

    return next.handle().pipe(
      tap(() => {
        // Optionally log response details after handling
        // this.logger.log(
        //   concatStr([req.method, req.originalUrl, res.statusCode]),
        // );
      }),
    );
  }
}
