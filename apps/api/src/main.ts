import { loadEnvironment } from '@identity/config';

import { createApplication } from './application.js';

/**
 * Startup.
 *
 * The environment is parsed before Nest builds anything, so a misconfigured deployment fails here
 * with every problem listed rather than on the first request that happens to read a missing value.
 */
const bootstrap = async (): Promise<void> => {
  const environment = loadEnvironment();
  const app = await createApplication(environment);
  app.enableShutdownHooks();

  await app.listen(environment.PORT, environment.HOST);
  process.stdout.write(
    `[identity] ${environment.APP_NAME} ${environment.APP_VERSION} (${environment.BUILD_SHA}) ` +
      `listening on ${environment.HOST}:${String(environment.PORT)}\n`,
  );
};

void bootstrap();
