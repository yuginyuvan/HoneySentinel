package com.honeypot.gateway.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class GatewayRoutingController {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    @Value("${services.attack-service.url:http://localhost:8081}")
    private String attackServiceUrl;

    @Value("${services.analytics-service.url:http://localhost:8083}")
    private String analyticsServiceUrl;

    @Value("${services.ml-service.url:http://localhost:8000}")
    private String mlServiceUrl;

    public GatewayRoutingController(
            RestClient restClient,
            ObjectMapper objectMapper) {

        this.restClient = restClient;
        this.objectMapper = objectMapper;
    }

    // ============================================================
    // MAIN ROUTER
    // ============================================================

    @RequestMapping(
            value = "/api/**",
            method = {
                    RequestMethod.GET,
                    RequestMethod.POST,
                    RequestMethod.PUT,
                    RequestMethod.DELETE,
                    RequestMethod.PATCH,
                    RequestMethod.OPTIONS
            }
    )
    public ResponseEntity<?> routeRequest(
            HttpServletRequest request) {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return ResponseEntity.ok().build();
        }

        String path = request.getRequestURI();

        String targetBaseUrl =
                resolveTargetService(path);

        if (targetBaseUrl == null) {

            Map<String, Object> error =
                    new LinkedHashMap<>();

            error.put(
                    "error",
                    "No route found for path: " + path
            );

            error.put("status", 404);

            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(error);
        }

        String queryString =
                request.getQueryString();

        String targetUrl =
                targetBaseUrl +
                        path +
                        (
                                queryString != null
                                        ? "?" + queryString
                                        : ""
                        );

        try {

            HttpMethod method =
                    HttpMethod.valueOf(
                            request.getMethod()
                    );

            byte[] bodyBytes =
                    request.getInputStream()
                            .readAllBytes();

            String body =
                    new String(
                            bodyBytes,
                            StandardCharsets.UTF_8
                    );

            System.out.println();
            System.out.println(
                    "=================================================="
            );
            System.out.println(
                    "[GATEWAY] Incoming Request"
            );
            System.out.println(
                    "[GATEWAY] Method      : " + method
            );
            System.out.println(
                    "[GATEWAY] Source Path : " + path
            );
            System.out.println(
                    "[GATEWAY] Target      : " + targetBaseUrl
            );
            System.out.println(
                    "[GATEWAY] Final URL   : " + targetUrl
            );
            System.out.println(
                    "[GATEWAY] Body Bytes  : " + bodyBytes.length
            );

            if (bodyBytes.length > 0) {
                System.out.println(
                        "[GATEWAY] Body        : " + body
                );
            }

            // ====================================================
            // AI REQUEST
            // ====================================================

            if (path.startsWith("/api/ai/")
                    && bodyBytes.length > 0) {

                return forwardAiRequest(
                        method,
                        targetUrl,
                        body
                );
            }

            // ====================================================
            // NORMAL REQUEST
            // ====================================================

            HttpHeaders headers =
                    new HttpHeaders();

            Enumeration<String> headerNames =
                    request.getHeaderNames();

            while (
                    headerNames != null
                            && headerNames.hasMoreElements()
            ) {

                String name =
                        headerNames.nextElement();

                if (
                        name.equalsIgnoreCase("host")
                                || name.equalsIgnoreCase(
                                "content-length"
                        )
                                || name.equalsIgnoreCase(
                                "transfer-encoding"
                        )
                                || name.equalsIgnoreCase(
                                "origin"
                        )
                ) {
                    continue;
                }

                headers.addAll(
                        name,
                        Collections.list(
                                request.getHeaders(name)
                        )
                );
            }

            RestClient.RequestBodySpec requestSpec =
                    restClient
                            .method(method)
                            .uri(URI.create(targetUrl))
                            .headers(
                                    h -> h.addAll(headers)
                            );

            if (bodyBytes.length > 0) {
                requestSpec.body(bodyBytes);
            }

            ResponseEntity<byte[]> response =
                    requestSpec
                            .retrieve()
                            .toEntity(byte[].class);

            return ResponseEntity
                    .status(response.getStatusCode())
                    .headers(response.getHeaders())
                    .body(response.getBody());

        } catch (
                HttpClientErrorException |
                HttpServerErrorException e
        ) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(e.getResponseBodyAsString());

        } catch (ResourceAccessException e) {

            return serviceUnavailable(
                    targetBaseUrl,
                    path,
                    e.getMessage()
            );

        } catch (Exception e) {

            e.printStackTrace();

            Map<String, Object> error =
                    new LinkedHashMap<>();

            error.put(
                    "error",
                    "Gateway Routing Error"
            );

            error.put(
                    "message",
                    e.getMessage()
            );

            error.put(
                    "status",
                    500
            );

            return ResponseEntity
                    .status(
                            HttpStatus.INTERNAL_SERVER_ERROR
                    )
                    .body(error);
        }
    }

    // ============================================================
    // AI REQUEST
    // IMPORTANT:
    // Uses HttpURLConnection instead of RestClient.
    // Explicit fixed Content-Length.
    // ============================================================

    private ResponseEntity<?> forwardAiRequest(
            HttpMethod method,
            String targetUrl,
            String body) throws Exception {

        System.out.println();
        System.out.println(
                "[GATEWAY] ================================"
        );
        System.out.println(
                "[GATEWAY] AI REQUEST FORWARDER"
        );
        System.out.println(
                "[GATEWAY] ================================"
        );

        System.out.println(
                "[GATEWAY] ML Target : " + targetUrl
        );

        // --------------------------------------------------------
        // Parse incoming JSON
        // --------------------------------------------------------

        JsonNode jsonNode =
                objectMapper.readTree(body);

        if (jsonNode == null || jsonNode.isNull()) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Empty JSON body"
                            )
                    );
        }

        if (
                !jsonNode.has("command")
                        || jsonNode
                        .get("command")
                        .isNull()
        ) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Missing required field: command"
                            )
                    );
        }

        String command =
                jsonNode
                        .get("command")
                        .asText();

        System.out.println(
                "[GATEWAY] Command : " + command
        );

        // --------------------------------------------------------
        // Create NEW JSON
        // --------------------------------------------------------

        Map<String, String> mlRequest =
                new LinkedHashMap<>();

        mlRequest.put(
                "command",
                command
        );

        String mlJson =
                objectMapper.writeValueAsString(
                        mlRequest
                );

        byte[] requestBytes =
                mlJson.getBytes(
                        StandardCharsets.UTF_8
                );

        System.out.println(
                "[GATEWAY] ML JSON : " + mlJson
        );

        System.out.println(
                "[GATEWAY] ML Body Bytes : "
                        + requestBytes.length
        );

        // --------------------------------------------------------
        // OPEN RAW HTTP CONNECTION
        // --------------------------------------------------------

        URL url =
                new URL(targetUrl);

        HttpURLConnection connection =
                (HttpURLConnection)
                        url.openConnection();

        connection.setRequestMethod(
                method.name()
        );

        connection.setDoOutput(true);

        connection.setDoInput(true);

        connection.setUseCaches(false);

        connection.setConnectTimeout(5000);

        connection.setReadTimeout(15000);

        // --------------------------------------------------------
        // IMPORTANT HEADERS
        // --------------------------------------------------------

        connection.setRequestProperty(
                "Content-Type",
                "application/json"
        );

        connection.setRequestProperty(
                "Accept",
                "application/json"
        );

        connection.setRequestProperty(
                "Connection",
                "close"
        );

        // --------------------------------------------------------
        // MOST IMPORTANT LINE
        //
        // This prevents chunked transfer encoding.
        // --------------------------------------------------------

        connection.setFixedLengthStreamingMode(
                requestBytes.length
        );

        System.out.println(
                "[GATEWAY] Content-Type : application/json"
        );

        System.out.println(
                "[GATEWAY] Content-Length : "
                        + requestBytes.length
        );

        System.out.println(
                "[GATEWAY] Transfer-Encoding : FIXED LENGTH"
        );

        // --------------------------------------------------------
        // SEND BODY
        // --------------------------------------------------------

        System.out.println(
                "[GATEWAY] Sending request to ML..."
        );

        try (
                var outputStream =
                        connection.getOutputStream()
        ) {

            outputStream.write(
                    requestBytes
            );

            outputStream.flush();
        }

        // --------------------------------------------------------
        // READ RESPONSE
        // --------------------------------------------------------

        int statusCode =
                connection.getResponseCode();

        System.out.println(
                "[GATEWAY] ML HTTP Status : "
                        + statusCode
        );

        InputStream inputStream;

        if (statusCode >= 400) {

            inputStream =
                    connection.getErrorStream();

        } else {

            inputStream =
                    connection.getInputStream();
        }

        String responseBody = "";

        if (inputStream != null) {

            try (inputStream) {

                responseBody =
                        new String(
                                inputStream.readAllBytes(),
                                StandardCharsets.UTF_8
                        );
            }
        }

        System.out.println(
                "[GATEWAY] ML Response : "
                        + responseBody
        );

        // --------------------------------------------------------
        // RETURN RESPONSE
        // --------------------------------------------------------

        MediaType contentType =
                MediaType.APPLICATION_JSON;

        return ResponseEntity
                .status(statusCode)
                .contentType(contentType)
                .body(responseBody);
    }

    // ============================================================
    // HEALTH
    // ============================================================

    @GetMapping("/health")
    public ResponseEntity<?> health() {

        Map<String, Object> status =
                new LinkedHashMap<>();

        status.put(
                "status",
                "UP"
        );

        status.put(
                "gateway",
                "UP"
        );

        status.put(
                "port",
                8080
        );

        Map<String, String> routes =
                new LinkedHashMap<>();

        routes.put(
                "/api/attacks/**",
                attackServiceUrl
        );

        routes.put(
                "/api/logs/**",
                attackServiceUrl
        );

        routes.put(
                "/api/reports/**",
                attackServiceUrl
        );

        routes.put(
                "/api/dashboard/**",
                analyticsServiceUrl
        );

        routes.put(
                "/api/ai/**",
                mlServiceUrl
        );

        status.put(
                "routes",
                routes
        );

        return ResponseEntity.ok(status);
    }

    // ============================================================
    // ROUTING
    // ============================================================

    private String resolveTargetService(
            String path) {

        // --------------------------------------------------------
        // ATTACK SERVICE
        // --------------------------------------------------------

        if (
                path.startsWith("/api/attacks")
                        || path.startsWith("/api/logs")
                        || path.startsWith("/api/reports")
        ) {

            return attackServiceUrl;
        }

        // --------------------------------------------------------
        // ANALYTICS SERVICE
        // --------------------------------------------------------

        if (
                path.startsWith("/api/dashboard")
        ) {

            return analyticsServiceUrl;
        }

        // --------------------------------------------------------
        // ML SERVICE
        // --------------------------------------------------------

        if (
                path.startsWith("/api/ai")
        ) {

            return mlServiceUrl;
        }

        return null;
    }

    // ============================================================
    // SERVICE UNAVAILABLE
    // ============================================================

    private ResponseEntity<?> serviceUnavailable(
            String target,
            String path,
            String message) {

        Map<String, Object> error =
                new LinkedHashMap<>();

        error.put(
                "error",
                "Service unavailable"
        );

        error.put(
                "target",
                target
        );

        error.put(
                "path",
                path
        );

        error.put(
                "message",
                message
        );

        error.put(
                "status",
                503
        );

        return ResponseEntity
                .status(
                        HttpStatus.SERVICE_UNAVAILABLE
                )
                .body(error);
    }
}