// Also embedded in README.md by scripts/update-guides.mjs.
export const requestIdGuides = [
  {
    id: 'spring', name: 'Spring Boot',
    note: 'Spring Boot 3+, synchronous Servlet MVC. Put this class in a scanned package and the logging property in application.properties. For @Async, reactive work, or worker pools, use Micrometer Tracing/context propagation; MDC is thread-local.',
    source: 'https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html',
    language: 'java',
    code: `import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RequestIdFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String incoming = request.getHeader("X-Request-ID");
        String id = incoming != null && incoming.matches("[A-Za-z0-9._-]{1,128}")
            ? incoming : UUID.randomUUID().toString();
        String previous = MDC.get("requestId");
        MDC.put("requestId", id);
        response.setHeader("X-Request-ID", id);
        try {
            chain.doFilter(request, response);
        } finally {
            if (previous == null) MDC.remove("requestId");
            else MDC.put("requestId", previous);
        }
    }
}

// application.properties (separate file):
// logging.pattern.console=%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} %-5level %logger{36} requestId=%X{requestId} %msg%n`
  },
  {
    id: 'express', name: 'Express',
    note: 'Node 18+, Express 4/5, ES modules. Install this middleware before routes. Call log() inside request work so async operations inherit the ID. The finish event writes the same ID explicitly.',
    source: 'https://nodejs.org/api/async_context.html#class-asynclocalstorage',
    language: 'javascript',
    code: `import express from 'express';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

const app = express();
const context = new AsyncLocalStorage();
function log(level, message) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(),
    level, message, requestId: context.getStore()?.requestId }));
}
app.use((req, res, next) => {
  const incoming = req.get('X-Request-ID');
  const requestId = /^[A-Za-z0-9._-]{1,128}$/.test(incoming ?? '')
    ? incoming : randomUUID();
  res.setHeader('X-Request-ID', requestId);
  res.on('finish', () => console.log(JSON.stringify({
    timestamp: new Date().toISOString(), level: 'INFO',
    message: 'HTTP ' + res.statusCode, requestId
  })));
  context.run({ requestId }, next);
});
app.get('/example', (req, res) => {
  log('INFO', 'Example requested');
  res.json({ ok: true });
});
app.listen(3000);`
  },
  {
    id: 'django', name: 'Django',
    note: 'Save as myapp/request_ids.py. Add myapp.request_ids.RequestIdMiddleware near the start of MIDDLEWARE. The sync middleware also works through Django’s ASGI adaptation; streaming iterators and background tasks need explicit context propagation. Merge the shown handler/filter configuration into your existing LOGGING setting.',
    source: 'https://docs.djangoproject.com/en/5.2/topics/http/middleware/',
    language: 'python',
    code: `import logging
import re
import time
from contextvars import ContextVar
from uuid import uuid4

request_id = ContextVar("request_id", default="-")

class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id.get()
        return True

class UtcFormatter(logging.Formatter):
    converter = time.gmtime

class RequestIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.headers.get("X-Request-ID", "")
        value = incoming if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", incoming) else str(uuid4())
        token = request_id.set(value)
        try:
            response = self.get_response(request)
            response["X-Request-ID"] = value
            logging.getLogger("myapp").info("HTTP %s", response.status_code)
            return response
        finally:
            request_id.reset(token)

# settings.py (separate file):
LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "filters": {"request_id": {"()": "myapp.request_ids.RequestIdFilter"}},
    "formatters": {"request": {
        "()": "myapp.request_ids.UtcFormatter",
        "format": "%(asctime)sZ %(levelname)s %(name)s request_id=%(request_id)s %(message)s",
        "datefmt": "%Y-%m-%dT%H:%M:%S",
    }},
    "handlers": {"console": {"class": "logging.StreamHandler",
        "filters": ["request_id"], "formatter": "request"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}`
  },
  {
    id: 'nginx', name: 'nginx',
    note: 'Put log_format in http {}, and the remaining directives in the server/location that proxies your application. Check inherited add_header directives when merging. Use the generated edge ID consistently; the backend should preserve X-Request-ID and log it too.',
    source: 'https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format',
    language: 'nginx',
    code: `# Inside http {}:
log_format bugparcel escape=json
    '{"timestamp":"$time_iso8601","level":"INFO",'
    '"request_id":"$request_id","message":"$request",'
    '"status":$status,"duration":$request_time}';

# Inside your server {} or proxying location {}:
access_log /var/log/nginx/bugparcel.log bugparcel;
proxy_set_header X-Request-ID $request_id;
proxy_hide_header X-Request-ID;
add_header X-Request-ID $request_id always;
# Keep your existing proxy_pass directive.`
  }
];
