import type { NestExpressApplication } from '@nestjs/platform-express';

/**
 * How many proxies stand between the internet and this process, and are trusted to say who the
 * client was.
 *
 * Exactly one: the load balancer. The deployment is `Internet → ALB → Identity task`, and the
 * task's port is reachable from the load balancer's security group and from nothing else. So the
 * immediate peer of every connection is the ALB, and the ALB is the only party whose word about
 * the client is worth anything.
 *
 * **Why this matters more here than almost anywhere.** `request.ip` is the `ip` dimension of
 * Platform's `login-per-ip` rate limit (ten attempts in fifteen minutes) and the address recorded
 * on every session and every login audit event. Without this setting Express reports the socket's
 * peer — the ALB node's private address — so every person signing in shares a handful of
 * buckets, the eleventh sign-in across the whole organisation in a quarter of an hour is refused,
 * and every session records the load balancer as where it came from.
 *
 * **Why a hop count, and why not `true`.** The ALB *appends* the address it accepted the
 * connection from to `X-Forwarded-For`; it does not replace what the client sent. A client can
 * therefore put any address it likes at the front of the header, and only the rightmost entry is
 * a fact. Trusting one hop makes Express take exactly that entry and ignore everything to its
 * left. `true` would take the leftmost — the client's own claim — and turn the rate limit into a
 * header a script rotates per request. A larger count would do the same thing more quietly,
 * trusting an entry no proxy of ours wrote.
 *
 * **What it relies on**, stated so a change to the deployment knows what it is changing:
 *
 * - the ALB keeps its default `X-Forwarded-For` processing mode, `append`. `preserve` would pass
 *   the client's header through untouched and make the rightmost entry the client's claim again;
 * - nothing but the ALB can open a connection to this port. A client that reached the task
 *   directly would itself be "the one trusted hop" and could name its own address. In ECS that is
 *   the security group's job; under `docker compose` it is the front door's, whose network the
 *   service shares and whose port it does not publish;
 * - there is one proxy, not two. A CDN in front of the ALB, or Caddy behind it, is a second hop
 *   and needs this number changed with it — otherwise every client is reported as that proxy.
 *
 * Without a proxy at all — `pnpm dev` on a laptop — nothing sends the header and `request.ip` is
 * the socket's peer, exactly as before.
 *
 * Nothing else reads what this setting changes: no route consults `request.protocol`,
 * `request.secure` or `request.hostname`, and the cookies are `Secure` unconditionally.
 */
export const TRUSTED_PROXY_HOPS = 1;

/** Applied once, at the composition root, before the server listens. */
export const trustLoadBalancer = (app: NestExpressApplication): void => {
  app.set('trust proxy', TRUSTED_PROXY_HOPS);
};
