package dev.bugparcel.api;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.net.URI;
import java.util.Set;

/** Loopback only, same-origin JSON writes, and no external resources in the interface. */
@Component
public class LocalRequestGuard extends OncePerRequestFilter {
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
        res.setHeader("Cache-Control","no-store"); res.setHeader("X-Content-Type-Options","nosniff");
        res.setHeader("Referrer-Policy","no-referrer"); res.setHeader("X-Frame-Options","DENY");
        res.setHeader("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        String host=req.getServerName();
        if(!Set.of("localhost","127.0.0.1","[::1]","::1").contains(host)) {res.sendError(403);return;}
        String origin=req.getHeader("Origin");
        if(origin!=null) {
            try {
                URI uri=URI.create(origin); int port=uri.getPort()<0?("https".equals(uri.getScheme())?443:80):uri.getPort();
                if(!req.getScheme().equals(uri.getScheme()) || !host.equals(uri.getHost()) || req.getServerPort()!=port) {res.sendError(403);return;}
            } catch(IllegalArgumentException e) {res.sendError(403);return;}
        }
        if(req.getRequestURI().startsWith("/api/") && !Set.of("GET","HEAD","POST").contains(req.getMethod())) {res.sendError(405);return;}
        if(req.getMethod().equals("POST")) {
            if("cross-site".equals(req.getHeader("Sec-Fetch-Site"))) {res.sendError(403);return;}
            if(req.getContentType()==null || !req.getContentType().toLowerCase(java.util.Locale.ROOT).startsWith("application/json")) {res.sendError(415);return;}
            if(req.getContentLengthLong()>RequestSizeLimit.MAX_BYTES) {res.sendError(413);return;}
            chain.doFilter(new RequestSizeLimit(req),res);
            return;
        }
        chain.doFilter(req,res);
    }
}
