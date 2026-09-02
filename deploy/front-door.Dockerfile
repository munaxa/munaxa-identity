# The front door, as a self-contained image.
#
# In compose the Caddyfile is bind-mounted; Render has no bind mounts, so the configuration is baked
# in. That is the only difference — the routing, the upstreams and the security headers are the same
# file, and the upstreams stay environment variables so the same image serves compose and Render
# without a fork.
#
# Nothing private is installed here, which is why this one image can be built by Render directly:
# the application images need the GitHub Packages credential as a BuildKit secret, which Render's
# builder does not implement, so those are built in CI and deployed by digest instead.
FROM caddy:2-alpine

COPY Caddyfile /etc/caddy/Caddyfile

# Caddy obtains and renews the certificate itself over ACME once PUBLIC_HOST resolves publicly and
# :80 and :443 are reachable. Render terminates TLS at its own edge for the service's onrender.com
# hostname; for a custom domain the certificate Caddy holds is the one browsers see.
EXPOSE 80 443

# Catch a malformed Caddyfile at build time rather than discovering it when the service starts and
# serves nothing. The site block is `{$PUBLIC_HOST} { … }`, so with no value the header collapses to
# nothing and every directive inside it lands at global scope — the file only parses once a host is
# substituted. `validate.invalid` is supplied for the syntax check alone: `.invalid` is reserved by
# RFC 2606 precisely so it can never resolve, and the value is not persisted into the image.
RUN PUBLIC_HOST=validate.invalid caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    || (echo 'Caddyfile failed validation' && exit 1)
