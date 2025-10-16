# Deploying LocalCA Behind Traefik Reverse Proxy

This guide explains how to deploy LocalCA behind a Traefik reverse proxy with a custom path prefix (e.g., `/localca`).

## Overview

When deploying LocalCA behind a reverse proxy like Traefik with a path prefix, Django needs to be aware of this prefix to generate correct URLs for links, forms, and static files. This is accomplished using the `URL_PREFIX` environment variable.

## Key Concepts

1. **URL_PREFIX**: This environment variable tells Django what URL prefix to use when generating URLs
2. **Strip Prefix Middleware**: Traefik strips the path prefix before forwarding to Django
3. **Django URL Generation**: With URL_PREFIX set, Django automatically prepends the prefix to all generated URLs

Note: We use `URL_PREFIX` instead of `SCRIPT_NAME` to avoid conflicts with WSGI's `SCRIPT_NAME` environment variable, which is used for request path validation. When Traefik strips the prefix, the incoming request paths don't include the prefix, which would cause errors with WSGI's `SCRIPT_NAME` validation.

## Configuration Steps

### 1. Set the URL_PREFIX Environment Variable

Add the `URL_PREFIX` environment variable to your LocalCA container:

```yaml
environment:
  - URL_PREFIX=/localca  # Set to your desired path prefix
  - CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://yourdomain.com/localca
```

### 2. Configure Traefik Labels

Configure your Traefik labels to:
- Match requests to your path prefix
- Strip the prefix before forwarding to Django
- Handle static files separately

```yaml
labels:
  - "traefik.enable=true"
  
  # Main application router
  - "traefik.http.routers.localca.rule=Host(`yourdomain.com`) && PathPrefix(`/localca`)"
  - "traefik.http.routers.localca.entrypoints=websecure"
  - "traefik.http.routers.localca.tls=true"
  
  # Strip prefix middleware
  - "traefik.http.middlewares.localca-stripprefix.stripprefix.prefixes=/localca"
  - "traefik.http.routers.localca.middlewares=localca-stripprefix"
  
  # Service configuration
  - "traefik.http.services.localca.loadbalancer.server.port=8000"
```

### 3. Configure Static Files

Static files need special handling. You have two options:

#### Option A: Nginx Container (Recommended)

Use a separate nginx container to serve static files:

```yaml
nginx:
  image: nginx:alpine
  volumes:
    - static_volume:/usr/share/nginx/html/static:ro
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.localca-static.rule=Host(`yourdomain.com`) && PathPrefix(`/localca/static`)"
    - "traefik.http.routers.localca-static.entrypoints=websecure"
    - "traefik.http.routers.localca-static.tls=true"
    - "traefik.http.middlewares.localca-static-strip.stripprefix.prefixes=/localca"
    - "traefik.http.routers.localca-static.middlewares=localca-static-strip"
```

#### Option B: Let Django Serve Static Files (Development Only)

For development/testing, you can let Django serve static files. Add WhiteNoise middleware (already included in LocalCA).

## Complete Example

See the included `docker-compose-traefik.yml` file for a complete working example.

## Troubleshooting

### Problem: 404 Errors

**Symptom**: Getting 404 errors when accessing LocalCA through Traefik

**Solutions**:
1. Verify `URL_PREFIX` environment variable is set correctly (must start with `/`)
2. Check that the Traefik path prefix matches the `URL_PREFIX` value
3. Ensure the strip prefix middleware is configured correctly

### Problem: Links Don't Include the Prefix

**Symptom**: Generated URLs don't include `/localca` prefix

**Solutions**:
1. Verify `URL_PREFIX` environment variable is set in the container
2. Check container logs to ensure Django is reading the environment variable
3. Restart the container after changing environment variables

### Problem: Static Files Return 404

**Symptom**: CSS, JavaScript, and images don't load

**Solutions**:
1. Ensure static files are collected: `python manage.py collectstatic --noinput`
2. Check that the nginx container has access to the static_volume
3. Verify Traefik routes for static files are configured
4. Check that static file path includes the prefix: `/localca/static/...`

### Problem: CSRF Verification Failed

**Symptom**: Forms return CSRF verification errors

**Solutions**:
1. Add your full domain URL to `CSRF_TRUSTED_ORIGINS`
2. Include both base domain and path: `https://domain.com,https://domain.com/localca`
3. Ensure the Origin/Referer headers match the trusted origins

## Testing Your Configuration

1. Access your LocalCA instance at: `https://yourdomain.com/localca`
2. Check that the homepage loads correctly
3. Verify all navigation links include the `/localca` prefix
4. Check browser developer tools to ensure static files load from `/localca/static/...`
5. Test form submissions (login, create certificates) to verify CSRF protection works

## Docker Swarm / Stack Deployment

For Docker Swarm deployments, use the same configuration but deploy as a stack:

```bash
docker stack deploy -c docker-compose-traefik.yml localca
```

## Advanced Configuration

### Multiple Path Prefixes

If you need to serve LocalCA at multiple paths, create separate router configurations for each path.

### Custom Static File Location

To use a custom static file location, modify the `STATIC_URL` setting through environment variables (already handled by LocalCA's settings.py).

### HTTPS Only

To force HTTPS, add these Traefik labels:

```yaml
- "traefik.http.middlewares.localca-https.redirectscheme.scheme=https"
- "traefik.http.routers.localca-http.middlewares=localca-https"
```

## Additional Resources

- [Django FORCE_SCRIPT_NAME Documentation](https://docs.djangoproject.com/en/5.1/ref/settings/#force-script-name)
- [Traefik PathPrefix Documentation](https://doc.traefik.io/traefik/routing/routers/#rule)
- [Traefik StripPrefix Middleware](https://doc.traefik.io/traefik/middlewares/http/stripprefix/)

## Why URL_PREFIX Instead of SCRIPT_NAME?

In earlier versions, this guide recommended using the `SCRIPT_NAME` environment variable. However, this causes issues because:

1. The WSGI specification uses `SCRIPT_NAME` to validate incoming request paths
2. When Traefik strips the prefix (e.g., `/localca`), Django receives paths like `/` 
3. Django's CommonMiddleware checks if the path starts with `os.environ['SCRIPT_NAME']`
4. This validation fails with the error: "Request path '/' does not start with SCRIPT_NAME '/localca'"

By using `URL_PREFIX` instead, we:
- Avoid conflicts with WSGI's `SCRIPT_NAME` validation
- Still get proper URL generation through Django's `FORCE_SCRIPT_NAME` setting
- Allow Traefik to strip the prefix without causing errors
