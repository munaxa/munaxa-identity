/**
 * Injection tokens.
 *
 * Symbols rather than strings so two providers can never collide silently, and declared in one
 * file so the wiring surface of the service is visible in one place.
 */
export const ENVIRONMENT = Symbol('identity.environment');
export const SECURITY_STACK = Symbol('identity.securityStack');
export const LOGGER = Symbol('identity.logger');
/** Company sign-in's provider catalogue and HTTP client; the default when nothing is bound. */
export const SSO_OPTIONS = Symbol('identity.ssoOptions');
