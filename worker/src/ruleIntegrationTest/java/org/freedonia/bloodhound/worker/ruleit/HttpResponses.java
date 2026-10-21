package org.freedonia.bloodhound.worker.ruleit;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;

/**
 * One router for port 80 and port 443. Hostnames are bare, so exposure alt-port URLs stay valid.
 * HTTPS is served with a trusted certificate; plain HTTP is the fallback and the redirect probe.
 */
public final class HttpResponses {

    static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    private static final byte[] REPORT_PDF = reportPdf();
    private static final byte[] ZIP_MAGIC = new byte[] {'P', 'K', 3, 4, 20, 0, 0, 0};
    private static final String ACTUATOR = "application/vnd.spring-boot.actuator.v3+json";
    private static final String LARAVEL_BASELINE =
            "<!DOCTYPE html><div class=\"whoops-container\"><h1>Whoops!</h1><p>probe-baseline</p></div>";

    public record Request(String method, String path, String host, Map<String, List<String>> headers, String rawHead) {}

    public record Response(int status, String contentType, byte[] body, Map<String, List<String>> headers) {}

    private HttpResponses() {}

    public static Response route(boolean tls, Request request) {
        String host = request.host();
        String path = request.path();
        String method = request.method().toUpperCase(Locale.ROOT);
        if (FixtureHosts.HEADERS_MISSING.equals(host)) {
            return headersMissing(method, request);
        }
        if (FixtureHosts.HEADERS_CSP.equals(host)) {
            return headersCsp(tls, method);
        }
        if (FixtureHosts.EXPOSURE.equals(host)) {
            return exposure(method, path);
        }
        if (FixtureHosts.EXPOSURE_INDEX.equals(host)) {
            return exposureIndex(path);
        }
        if (FixtureHosts.DOCS.equals(host)) {
            return docs(path);
        }
        if (host.startsWith("tls-")) {
            return tlsHost(host);
        }
        return text(404, "text/plain", "not-found\n");
    }

    private static Response headersMissing(String method, Request request) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Server", List.of("Apache/2.4.41"));
        headers.put("Set-Cookie", List.of("session=abc", "auth=1; Secure"));
        List<String> origin = request.headers().get("origin");
        if (origin != null && !origin.isEmpty()) {
            headers.put("Access-Control-Allow-Origin", List.of(origin.get(0)));
            headers.put("Access-Control-Allow-Credentials", List.of("true"));
        }
        if ("TRACE".equals(method)) {
            return new Response(200, "message/http", request.rawHead().getBytes(StandardCharsets.ISO_8859_1), headers);
        }
        return new Response(200, "text/html", "<html>missing</html>".getBytes(StandardCharsets.UTF_8), headers);
    }

    private static Response headersCsp(boolean tls, String method) {
        if (!tls) {
            return text(301, "text/plain", "see https\n", "Location", "https://" + FixtureHosts.HEADERS_CSP + "/");
        }
        if ("TRACE".equals(method)) {
            return text(405, "text/plain", "method not allowed\n");
        }
        return text(
                200,
                "text/html",
                "<html>csp</html>",
                "Content-Security-Policy",
                "default-src * 'unsafe-inline' 'unsafe-eval'",
                "X-Frame-Options",
                "DENY",
                "X-Content-Type-Options",
                "nosniff",
                "Referrer-Policy",
                "no-referrer",
                "Permissions-Policy",
                "geolocation=()",
                "Cross-Origin-Opener-Policy",
                "same-origin",
                "Cross-Origin-Resource-Policy",
                "same-origin",
                "Set-Cookie",
                "__Host-session=1; Secure; HttpOnly; SameSite=Strict; Path=/");
    }

    private static Response exposure(String method, String path) {
        if (path.startsWith("/__bloodhound_probe_nonexistent_")) {
            return text(404, "text/html", LARAVEL_BASELINE);
        }
        if ("/".equals(path)) {
            return text(200, "text/html", "<html><script src=\"/app.js\"></script></html>");
        }
        if ("/app.js.map".equals(path)) {
            return text(200, "application/json", "{\"version\":3,\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}");
        }
        if ("POST".equals(method) && "/graphql".equals(path)) {
            return text(200, "application/json", "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}");
        }
        return switch (path) {
            case "/actuator/heapdump" -> text(200, "application/octet-stream", "heap");
            case "/actuator/env" -> text(200, ACTUATOR, "{\"propertySources\":[]}");
            case "/actuator/beans" -> text(200, ACTUATOR, "{\"beans\":[]}");
            case "/actuator/mappings" -> text(200, ACTUATOR, "{\"contexts\":{}}");
            case "/actuator/configprops" -> text(200, ACTUATOR, "{\"contexts\":{},\"beans\":[]}");
            case "/actuator/threaddump" -> text(200, ACTUATOR, "{\"threads\":[{\"threadName\":\"main\"}]}");
            case "/actuator/loggers" -> text(200, ACTUATOR, "{\"loggers\":{}}");
            case "/actuator/health" ->
                text(200, ACTUATOR, "{\"status\":\"UP\",\"components\":{\"disk\":{\"status\":\"UP\"}}}");
            case "/actuator/info" -> text(200, ACTUATOR, "{\"app\":\"bh\"}");
            case "/.git/config" ->
                text(
                        200,
                        "text/plain",
                        "[core]\nrepositoryformatversion = 0\naws_access_key_id="
                                + AWS_KEY
                                + "\n-----BEGIN RSA PRIVATE KEY-----\nMIIBdummy\n");
            case "/.env" -> text(200, "text/plain", "DB_PASSWORD=hunter2\npassword=\"abcdefghijklmnopqrstuv\"\n");
            case "/.aws/credentials" ->
                text(
                        200,
                        "text/plain",
                        "aws_access_key_id = " + AWS_KEY + "\naws_secret_access_key = " + AWS_SECRET + "\n");
            case "/v2/api-docs" -> text(200, "application/json", "{\"swagger\":\"2.0\"}");
            case "/phpmyadmin/" -> text(200, "text/html", "<html>phpMyAdmin<input name=\"pma_username\"></html>");
            case "/script" -> text(200, "text/html", "<html>Script Console Groovy script</html>");
            case "/app/kibana" -> text(200, "text/html", "<html kbn-injected-metadata=\"1\"></html>");
            case "/.well-known/security.txt" ->
                text(200, "text/plain", "Contact: mailto:security@example.test\nExpires: 2020-01-01T00:00:00Z\n");
            case "/.DS_Store" -> text(200, "application/octet-stream", "xxxxBud1yyyy");
            case "/backup/" -> text(200, "text/html", "<title>Index of /backup/</title>");
            case "/backup.zip" -> bytes(200, "application/zip", ZIP_MAGIC);
            case "/backup.sql" -> text(200, "text/plain", "-- MySQL dump\nCREATE TABLE IF NOT EXISTS t(id int);\n");
            case "/phpinfo.php" -> text(200, "text/html", "<html>phpinfo() PHP Version 8.2</html>");
            case "/id_rsa" -> text(200, "text/plain", "-----BEGIN RSA PRIVATE KEY-----\nMIIBdummy\n");
            case "/metrics" -> text(200, "text/plain", "# HELP requests_total\n# TYPE requests_total counter\n");
            case "/h2-console" -> text(200, "text/html", "<html>H2 Console Driver Class</html>");
            case "/telescope" -> text(200, "text/html", "<div id=\"telescope\"></div>");
            case "/trace.axd" -> text(200, "text/html", "Application Trace Requests to the Application");
            case "/elmah.axd" -> text(200, "text/html", "Error Log for /");
            case "/adminer.php" -> text(200, "text/html", "<input name=\"auth[driver]\">");
            default -> text(404, "text/plain", "exposure-miss\n");
        };
    }

    private static Response exposureIndex(String path) {
        if (path.startsWith("/__bloodhound_probe_nonexistent_")) {
            return text(404, "text/plain", "not-found-index\n");
        }
        if ("/".equals(path)) {
            return text(200, "text/html", "<html><p>index only</p></html>");
        }
        if ("/actuator".equals(path)) {
            return text(200, "application/json", "{\"_links\":{}}");
        }
        if ("/actuator/health".equals(path)) {
            return text(200, "application/json", "{\"status\":\"UP\"}");
        }
        return text(404, "text/plain", "index-miss\n");
    }

    private static Response docs(String path) {
        if ("/files/report.pdf".equals(path)) {
            return bytes(200, "application/pdf", REPORT_PDF);
        }
        return text(200, "text/html", "<html><a href=\"/files/report.pdf\">report</a></html>");
    }

    private static Response tlsHost(String host) {
        String hsts = switch (host) {
            case "tls-hsts-short.bh.test" -> "max-age=100";
            case "tls-hsts-preload.bh.test" -> "max-age=20000000; includeSubDomains; preload";
            case "tls-soon.bh.test" -> "max-age=31536000; includeSubDomains";
            default -> null;
        };
        if (hsts == null) {
            return text(200, "text/plain", "tls\n");
        }
        return text(200, "text/plain", "tls\n", "Strict-Transport-Security", hsts);
    }

    static Response text(int status, String contentType, String body, String... headerPairs) {
        return new Response(status, contentType, body.getBytes(StandardCharsets.UTF_8), pairs(headerPairs));
    }

    static Response bytes(int status, String contentType, byte[] body) {
        return new Response(status, contentType, body, Map.of());
    }

    private static Map<String, List<String>> pairs(String... headerPairs) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 0; i + 1 < headerPairs.length; i += 2) {
            headers.computeIfAbsent(headerPairs[i], key -> new ArrayList<>()).add(headerPairs[i + 1]);
        }
        return headers;
    }

    private static byte[] reportPdf() {
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage());
            PDDocumentInformation info = new PDDocumentInformation();
            info.setAuthor("Ada Lovelace");
            info.setCreator("/home/ada/work/report.pdf");
            doc.setDocumentInformation(info);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
