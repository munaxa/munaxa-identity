import { Controller, Get, Inject } from '@nestjs/common';

import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';
import type { IdentityEnvironment } from '@identity/config';

/**
 * Liveness and readiness, split because they answer different questions.
 *
 * `live` says the process is running and should not be restarted. `ready` says it can serve — it
 * touches the database, because an authentication service that cannot reach its accounts is not
 * ready no matter how healthy the process is, and a load balancer that cannot tell the difference
 * will happily send every sign-in to a replica that refuses all of them.
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
    await this.prisma.$queryRaw`select 1`;
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
