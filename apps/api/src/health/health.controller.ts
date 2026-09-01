import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';

import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import { probeReadiness } from './readiness.js';
import { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';
import type { IdentityEnvironment } from '@identity/config';

/**
 * Liveness and readiness, split because they answer different questions.
 *
 * `live` says the process is running and should not be restarted. `ready` says it can serve — it
 * touches the database *and* the cache, because an authentication service that cannot reach its
 * accounts is not ready no matter how healthy the process is, and a load balancer that cannot tell
 * the difference will happily send every sign-in to a replica that refuses all of them.
 *
 * The cache counts for the same reason the database does, and it was left out at first: with Redis
 * stopped, sign-in fails closed — nobody is authenticated, which is the important part — but it
 * fails with a 401, indistinguishable to the caller from a wrong password, while readiness went on
 * answering 200. Measured, not reasoned about: the environment was taken apart to see what the
 * probe would say.
 */
@Controller('auth/health')
export class HealthController {
  public constructor(
    private readonly prisma: PrismaService,
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
  ) {}

  @Get('live')
  public live(): Record<string, unknown> {
    return {
      status: 'ok',
      name: this.environment.APP_NAME,
      version: this.environment.APP_VERSION,
      build: this.environment.BUILD_SHA,
    };
  }

  @Get('ready')
  public async ready(): Promise<Record<string, unknown>> {
    const probe = await probeReadiness(this.prisma, this.security);
    if (!probe.ok) {
      // 503, not a thrown 500. This is "not ready yet", a state an orchestrator is expected to poll
      // through, not a defect in the request. The reason names a dependency, never a credential,
      // and the missing-table list is a schema fact rather than anything about a person.
      throw new ServiceUnavailableException({
        status: 'unavailable',
        reason: probe.failed,
        ...(probe.missing === undefined ? {} : { missing: probe.missing }),
      });
    }
    return {
      status: 'ok',
      version: this.environment.APP_VERSION,
      build: this.environment.BUILD_SHA,
      // Which mode the concurrency limit is in, because the difference between an exact limit and
      // a hint should be visible without reading the wiring.
      sessionLimit: this.security.limitEnforcement,
      cache: this.security.cacheKind,
      signingKid: this.security.signing.kid,
    };
  }
}
