import {
  Module,
  type MiddlewareConsumer,
  type NestModule,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { loadEnvironment, type IdentityEnvironment } from '@identity/config';

import { AuthController } from './auth/auth.controller.js';
import { AuthService } from './auth/auth.service.js';
import { HealthController } from './health/health.controller.js';
import { PrismaService } from './persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from './platform/security.js';
import { EdgeMiddleware } from './security/edge.middleware.js';
import { ENVIRONMENT, SECURITY_STACK } from './tokens.js';

/**
 * The application.
 *
 * The security stack is a single async provider rather than a dozen: every Platform service shares
 * a cache, a clock and a set of adapters, and constructing them apart would make it possible for
 * two of them to disagree about which store they are talking to.
 */
@Module({
  controllers: [AuthController, HealthController],
  providers: [
    PrismaService,
    AuthService,
    EdgeMiddleware,
    { provide: ENVIRONMENT, useFactory: (): IdentityEnvironment => loadEnvironment() },
    {
      provide: SECURITY_STACK,
      inject: [ENVIRONMENT, PrismaService],
      useFactory: (
        environment: IdentityEnvironment,
        prisma: PrismaService,
      ): Promise<SecurityStack> => buildSecurityStack(environment, prisma),
    },
  ],
  exports: [ENVIRONMENT, SECURITY_STACK, PrismaService],
})
export class AppModule implements NestModule, OnApplicationShutdown {
  public constructor() {}

  public configure(consumer: MiddlewareConsumer): void {
    // Every route, without exception. A route added later is protected by default rather than by
    // somebody remembering to list it.
    consumer.apply(EdgeMiddleware).forRoutes('*');
  }

  public onApplicationShutdown(): void {
    // The cache client is closed by the stack's own `close`; Nest disposes the Prisma client.
  }
}
