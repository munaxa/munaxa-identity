# The front door, as a self-contained image.
#
# In compose the Caddyfile is bind-mounted; Render has no bind mounts, so the configuration is baked
# in. That is the only difference — the routing, the upstreams and the security headers are the same
# snippet, and the upstreams stay environment variables so the same image serves compose and Render
# without a fork.
#
# Nothing private is installed here, which is why this one image can be built by Render directly:
# the application images need the GitHub Packages credential as a BuildKit secret, which Render's
# builder does not implement, so those are built in CI and deployed by digest instead.
FROM caddy:2-alpine

# `Caddyfile` is the edge-terminated form: it listens on $PORT and issues no certificate. Render
# provides and renews the certificate for a custom domain and terminates HTTPS at its own edge, so
# the public certificate is Render's and never Caddy's. `Caddyfile.tls` is carried alongside for a
# deployment that *is* the TLS endpoint; it is not the one Caddy loads here.
COPY Caddyfile Caddyfile.tls caddy-routes.caddyfile /etc/caddy/

# Render routes to the port the service listens on and sets PORT to tell it which. The default in
# the Caddyfile matches Render's own default; this EXPOSE documents it and nothing more.
EXPOSE 10000

# Catch a malformed configuration at build time rather than discovering it when the service starts
# and serves nothing. Both forms are validated: `Caddyfile.tls` only parses once a host is
# substituted — with no value its site header collapses to nothing and every directive inside lands
# at global scope — so `validate.invalid` is supplied for the syntax check alone. `.invalid` is
# reserved by RFC 2606 precisely so it can never resolve, and the value is not persisted.
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    || (echo 'Caddyfile failed validation' && exit 1)
RUN PUBLIC_HOST=validate.invalid caddy validate --config /etc/caddy/Caddyfile.tls --adapter caddyfile \
    || (echo 'Caddyfile.tls failed validation' && exit 1)
