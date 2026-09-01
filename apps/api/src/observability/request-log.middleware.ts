import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import type { Logger } from 'pino';

import { LOGGER } from '../tokens.js';

/**
 * One line per request, carrying the correlation id the edge assigned.
 *
 * Deliberately a summary rather than the request object: the fields are named, so nothing arrives
 * in a log because it happened to be on an object somebody serialised. The logger redacts by path
 * as a second line of defence, but the first is not logging it at all.
 *
 * The path is logged and the query string is not. A query string on this service is short and
 * mostly harmless — `?lang=ar` — but `?token=…` is exactly the kind of thing that appears one day
 * in someone else's integration, and a log that has never held one cannot leak one.
 */
@Injectable()
export class RequestLogMiddleware implements NestMiddleware {
  public constructor(@Inject(LOGGER) private readonly logger: Logger) {}

  public use(request: Request, response: Response, next: NextFunction): void {
    const startedAt = process.hrtime.bigint();

    response.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      const correlationId = (request as Request & { correlationId?: string }).correlationId;

      this.logger.info(
        {
          method: request.method,
          path: request.path,
          status: response.statusCode,
          durationMs: Math.round(durationMs),
          ...(correlationId === undefined ? {} : { correlationId }),
        },
        'request',
      );
    });
    next();
  }
}
