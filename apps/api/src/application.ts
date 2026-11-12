import 'reflect-metadata';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import type { IdentityEnvironment } from '@identity/config';

import { AppModule } from './app.module.js';

/**
 * The application exactly as `main.ts` serves it: proxy trust, cookies, both body encodings and the
 * `api` prefix. Shared with the HTTP-level tests so they exercise the production wiring.
 */
export const createApplication = async (
  environment: IdentityEnvironment,
  options: { readonly quiet?: boolean } = {},
): Promise<NestExpressApplication> => {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bodyParser: true,
    ...(options.quiet === true ? { logger: false as const } : {}),
  });

  // The client address the rate limiter counts is `request.ip`; behind a load balancer it is only
  // the client's when the balancer is trusted (see `TRUST_PROXY_HOPS`).
  app.set('trust proxy', environment.TRUST_PROXY_HOPS);
  app.use(cookieParser());
  // The sign-in page is a plain HTML form, so the service parses form encoding as well as JSON.
  // Without this a browser's post arrives with an empty body and every sign-in fails as though the
  // password were wrong — which is the least diagnosable version of that failure.
  app.useBodyParser('urlencoded', { extended: false });
  // The public origin routes /api/auth/* here; the prefix is part of the issuer URL and of the
  // refresh cookie's path, so it is not something a deployment may vary independently.
  app.setGlobalPrefix('api');
  return app;
};
