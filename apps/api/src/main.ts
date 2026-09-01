import 'reflect-metadata';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { loadEnvironment } from '@identity/config';

import { AppModule } from './app.module.js';

/**
 * Startup.
 *
 * The environment is parsed before Nest builds anything, so a misconfigured deployment fails here
 * with every problem listed rather than on the first request that happens to read a missing value.
 */
const bootstrap = async (): Promise<void> => {
  const environment = loadEnvironment();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: true });

  app.use(cookieParser());
  // The sign-in page is a plain HTML form, so the service parses form encoding as well as JSON.
  // Without this a browser's post arrives with an empty body and every sign-in fails as though the
  // password were wrong — which is the least diagnosable version of that failure.
  app.useBodyParser('urlencoded', { extended: false });
  // The public origin routes /api/auth/* here; the prefix is part of the issuer URL and of the
  // refresh cookie's path, so it is not something a deployment may vary independently.
  app.setGlobalPrefix('api');
  app.enableShutdownHooks();

  await app.listen(environment.PORT, environment.HOST);
  process.stdout.write(
    `[identity] ${environment.APP_NAME} ${environment.APP_VERSION} (${environment.BUILD_SHA}) ` +
      `listening on ${environment.HOST}:${String(environment.PORT)}\n`,
  );
};

void bootstrap();
