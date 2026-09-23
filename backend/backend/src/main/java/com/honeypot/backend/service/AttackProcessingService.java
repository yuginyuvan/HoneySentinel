package com.honeypot.backend.service;

import com.honeypot.backend.dto.CowrieEventDTO;
import com.honeypot.backend.model.*;
import com.honeypot.backend.repository.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class AttackProcessingService {

    private final AttackLogRepository attackLogRepository;
    private final AttackSessionRepository attackSessionRepository;
    private final AttackEventRepository attackEventRepository;
    private final CommandLogRepository commandLogRepository;
    private final CredentialAttemptRepository credentialAttemptRepository;
    private final DownloadedFileRepository downloadedFileRepository;
    private final AIAnalysisRepository aiAnalysisRepository;

    private final RestClient restClient;

    @Value("${ml.service.url:http://localhost:8000}")
    private String mlServiceUrl;

    public AttackProcessingService(
            AttackLogRepository attackLogRepository,
            AttackSessionRepository attackSessionRepository,
            AttackEventRepository attackEventRepository,
            CommandLogRepository commandLogRepository,
            CredentialAttemptRepository credentialAttemptRepository,
            DownloadedFileRepository downloadedFileRepository,
            AIAnalysisRepository aiAnalysisRepository
    ) {
        this.attackLogRepository = attackLogRepository;
        this.attackSessionRepository = attackSessionRepository;
        this.attackEventRepository = attackEventRepository;
        this.commandLogRepository = commandLogRepository;
        this.credentialAttemptRepository = credentialAttemptRepository;
        this.downloadedFileRepository = downloadedFileRepository;
        this.aiAnalysisRepository = aiAnalysisRepository;

        this.restClient = RestClient.builder().build();
    }


    // ============================================================
    // GENERIC ATTACK LOG PROCESSING
    // ============================================================

    @Transactional
    public AttackLog processAttack(AttackLog log) {

        if (log.getTimestamp() == null) {
            log.setTimestamp(LocalDateTime.now());
        }

        AttackLog savedLog = attackLogRepository.save(log);

        // Save general event
        AttackEvent event = new AttackEvent();

        event.setEventType(
                log.getEventId() != null
                        ? log.getEventId()
                        : "ATTACK_LOG"
        );

        event.setEventTimestamp(log.getTimestamp());

        event.setMessage(
                log.getMessage() != null
                        ? log.getMessage()
                        : log.getCommandInput()
        );

        event.setRawJson(log.getRawJson());

        attackEventRepository.save(event);


        // Process session-related information
        if (log.getSessionId() != null &&
                !log.getSessionId().trim().isEmpty()) {

            AttackSession session =
                    getOrCreateSession(
                            log.getSessionId(),
                            log.getSourceIp(),
                            log.getProtocol()
                    );


            // Credential attempt
            if (log.getUsername() != null ||
                    log.getPassword() != null) {

                CredentialAttempt cred =
                        new CredentialAttempt();

                cred.setSession(session);
                cred.setUsername(log.getUsername());
                cred.setPassword(log.getPassword());
                cred.setSuccess(false);
                cred.setAttemptTime(log.getTimestamp());

                credentialAttemptRepository.save(cred);
            }


            // Command
            if (log.getCommandInput() != null &&
                    !log.getCommandInput().trim().isEmpty()) {

                saveCommandAndClassify(
                        session,
                        log.getCommandInput(),
                        log.getTimestamp()
                );
            }
        }

        return savedLog;
    }


    // ============================================================
    // COWRIE EVENT PROCESSING
    // ============================================================

    @Transactional
    public AttackSession processCowrieEvent(CowrieEventDTO dto) {

        if (dto == null) {
            throw new IllegalArgumentException(
                    "Cowrie event cannot be null"
            );
        }

        LocalDateTime now =
                parseTimestamp(dto.getTimestamp());


        String sessionKey =
                dto.getSession() != null &&
                !dto.getSession().trim().isEmpty()
                        ? dto.getSession()
                        : "sess_" + System.currentTimeMillis();


        // --------------------------------------------------------
        // GET OR CREATE SESSION
        // --------------------------------------------------------

        AttackSession session =
                attackSessionRepository
                        .findByCowrieSessionId(sessionKey)
                        .orElseGet(() -> {

                            AttackSession s =
                                    new AttackSession();

                            s.setCowrieSessionId(sessionKey);

                            s.setSourceIp(
                                    dto.getSrcIp() != null
                                            ? dto.getSrcIp()
                                            : "127.0.0.1"
                            );

                            s.setSourcePort(
                                    dto.getSrcPort() != null
                                            ? dto.getSrcPort()
                                            : 22
                            );

                            s.setDestinationIp(
                                    dto.getDstIp() != null
                                            ? dto.getDstIp()
                                            : "0.0.0.0"
                            );

                            s.setDestinationPort(
                                    dto.getDstPort() != null
                                            ? dto.getDstPort()
                                            : 2222
                            );

                            s.setProtocol(
                                    dto.getProtocol() != null
                                            ? dto.getProtocol().toUpperCase()
                                            : "SSH"
                            );

                            s.setCountry(
                                    dto.getCountry() != null
                                            ? dto.getCountry()
                                            : "Unknown"
                            );

                            s.setCity(
                                    dto.getCity() != null
                                            ? dto.getCity()
                                            : "Unknown"
                            );

                            s.setLoginStatus("ATTEMPTED");

                            s.setLoginTime(now);

                            s.setCreatedAt(
                                    LocalDateTime.now()
                            );

                            return attackSessionRepository.save(s);
                        });


        String eventId =
                dto.getEventId() != null
                        ? dto.getEventId()
                        : "";


        // --------------------------------------------------------
        // SAVE GENERAL EVENT
        // --------------------------------------------------------

        AttackEvent event =
                new AttackEvent();

        event.setSessionId(
                session.getSessionId()
        );

        event.setEventType(eventId);

        event.setEventTimestamp(now);

        event.setMessage(
                dto.getMessage() != null
                        ? dto.getMessage()
                        : dto.getInput()
        );

        attackEventRepository.save(event);


        // --------------------------------------------------------
        // LOGIN SUCCESS
        // --------------------------------------------------------

        if (eventId.contains("login.success")) {

            session.setUsername(
                    dto.getUsername()
            );

            session.setPassword(
                    dto.getPassword()
            );

            session.setLoginStatus("SUCCESS");

            attackSessionRepository.save(session);


            CredentialAttempt cred =
                    new CredentialAttempt();

            cred.setSession(session);

            cred.setUsername(
                    dto.getUsername()
            );

            cred.setPassword(
                    dto.getPassword()
            );

            cred.setSuccess(true);

            cred.setAttemptTime(now);

            credentialAttemptRepository.save(cred);
        }


        // --------------------------------------------------------
        // LOGIN FAILED
        // --------------------------------------------------------

        else if (eventId.contains("login.failed")) {

            /*
             * Don't overwrite an already successful session.
             */
            if (!"SUCCESS".equalsIgnoreCase(
                    session.getLoginStatus())) {

                session.setLoginStatus("FAILED");

                if (session.getUsername() == null) {
                    session.setUsername(
                            dto.getUsername()
                    );
                }

                if (session.getPassword() == null) {
                    session.setPassword(
                            dto.getPassword()
                    );
                }

                attackSessionRepository.save(session);
            }


            CredentialAttempt cred =
                    new CredentialAttempt();

            cred.setSession(session);

            cred.setUsername(
                    dto.getUsername()
            );

            cred.setPassword(
                    dto.getPassword()
            );

            cred.setSuccess(false);

            cred.setAttemptTime(now);

            credentialAttemptRepository.save(cred);
        }


        // --------------------------------------------------------
        // COMMAND INPUT
        // --------------------------------------------------------

        else if (eventId.contains("command.input")) {

            saveCommandAndClassify(
                    session,
                    dto.getInput(),
                    now
            );
        }


        // --------------------------------------------------------
        // FILE DOWNLOAD
        // --------------------------------------------------------

        else if (eventId.contains("file_download")) {

            DownloadedFile file =
                    new DownloadedFile();

            file.setSession(session);

            file.setDownloadUrl(
                    dto.getUrl()
            );

            file.setFilename(
                    dto.getOutfile() != null
                            ? dto.getOutfile()
                            : "payload.bin"
            );

            file.setSha256Hash(
                    dto.getSha256()
            );

            file.setDownloadTime(now);

            downloadedFileRepository.save(file);
        }


        // --------------------------------------------------------
        // SESSION CLOSED
        // --------------------------------------------------------

        else if (eventId.contains("session.closed")) {

            session.setLogoutTime(now);

            if (dto.getDuration() != null) {

                session.setDurationSeconds(
                        dto.getDuration().intValue()
                );
            }

            attackSessionRepository.save(session);


            /*
             * IMPORTANT:
             *
             * Full AI analysis happens only once,
             * when the session is complete.
             */
            triggerSessionAIAnalysis(session);
        }


        // --------------------------------------------------------
        // SAVE RAW ATTACK LOG
        // --------------------------------------------------------

        AttackLog rawLog =
                new AttackLog();

        rawLog.setEventId(eventId);

        rawLog.setSessionId(sessionKey);

        rawLog.setSourceIp(
                session.getSourceIp()
        );

        rawLog.setSourcePort(
                session.getSourcePort()
        );

        rawLog.setUsername(
                dto.getUsername() != null
                        ? dto.getUsername()
                        : session.getUsername()
        );

        rawLog.setPassword(
                dto.getPassword() != null
                        ? dto.getPassword()
                        : session.getPassword()
        );

        rawLog.setProtocol(
                session.getProtocol()
        );

        rawLog.setCommandInput(
                dto.getInput()
        );

        rawLog.setMessage(
                dto.getMessage() != null
                        ? dto.getMessage()
                        : eventId
        );

        rawLog.setTimestamp(now);

        attackLogRepository.save(rawLog);


        return session;
    }


    // ============================================================
    // COMMAND CLASSIFICATION
    // ============================================================

    private void saveCommandAndClassify(
            AttackSession session,
            String commandInput,
            LocalDateTime timestamp
    ) {

        if (commandInput == null ||
                commandInput.trim().isEmpty()) {

            return;
        }


        CommandLog command =
                new CommandLog();

        command.setSession(session);

        command.setCommand(
                commandInput.trim()
        );

        command.setCommandTime(timestamp);


        // --------------------------------------------------------
        // ASK ML SERVICE
        // --------------------------------------------------------

        Map<String, Object> aiResult =
                callMLClassifyCommand(
                        commandInput
                );


        String riskLevel =
                getString(
                        aiResult,
                        "risk",
                        evaluateFallbackRisk(
                                commandInput
                        )
                );


        command.setRiskLevel(
                riskLevel
        );


        /*
         * IMPORTANT:
         *
         * We DO NOT create AIAnalysis here.
         *
         * CommandLog stores command-level
         * classification.
         *
         * Full AIAnalysis is created after
         * the session closes.
         */

        commandLogRepository.save(command);
    }


    // ============================================================
    // COMMAND ML API
    // ============================================================

    private Map<String, Object> callMLClassifyCommand(
            String command
    ) {

        try {

            Map<String, String> body =
                    Map.of(
                            "command",
                            command
                    );


            Map<String, Object> response =
                    restClient.post()

                            .uri(
                                    mlServiceUrl +
                                    "/api/ai/classify-command"
                            )

                            .contentType(
                                    MediaType.APPLICATION_JSON
                            )

                            .body(body)

                            .retrieve()

                            .body(Map.class);


            return response != null
                    ? response
                    : createFallbackResult(command);


        } catch (Exception e) {

            /*
             * ML service may be offline.
             *
             * Backend must still continue
             * collecting honeypot data.
             */

            return createFallbackResult(command);
        }
    }


    // ============================================================
    // FULL SESSION AI ANALYSIS
    // ============================================================

    private void triggerSessionAIAnalysis(
            AttackSession session
    ) {

        try {

            // ----------------------------------------------------
            // GET ALL COMMANDS
            // ----------------------------------------------------

            List<CommandLog> commands =
                    commandLogRepository
                            .findBySession_SessionId(
                                    session.getSessionId()
                            );


            List<Map<String, String>> commandList =
                    new ArrayList<>();


            for (CommandLog command : commands) {

                if (command.getCommand() == null) {
                    continue;
                }

                Map<String, String> item =
                        new HashMap<>();

                item.put(
                        "command",
                        command.getCommand()
                );

                if (command.getRiskLevel() != null) {

                    item.put(
                            "risk",
                            command.getRiskLevel()
                    );
                }

                commandList.add(item);
            }


            // ----------------------------------------------------
            // BUILD SESSION FEATURES
            // ----------------------------------------------------

            Map<String, Object> request =
                    new HashMap<>();


            request.put(
                    "sourceIp",
                    session.getSourceIp()
            );

            request.put(
                    "protocol",
                    session.getProtocol()
            );

            request.put(
                    "username",
                    session.getUsername()
            );

            request.put(
                    "loginStatus",
                    session.getLoginStatus()
            );

            request.put(
                    "durationSeconds",
                    session.getDurationSeconds()
            );

            request.put(
                    "commands",
                    commandList
            );


            /*
             * NOTE:
             *
             * We are not hardcoding failedLogins = 1 anymore.
             *
             * For the first version, derive the count from
             * the command/credential data available through
             * the session processing.
             *
             * We will make this exact using repository count
             * methods after verifying CredentialAttemptRepository.
             */

            request.put(
                    "successfulLogins",
                    "SUCCESS".equalsIgnoreCase(
                            session.getLoginStatus()
                    ) ? 1 : 0
            );


            // ----------------------------------------------------
            // CALL AI SERVICE
            // ----------------------------------------------------

            Map<String, Object> response =
                    restClient.post()

                            .uri(
                                    mlServiceUrl +
                                    "/api/ai/analyze-session"
                            )

                            .contentType(
                                    MediaType.APPLICATION_JSON
                            )

                            .body(request)

                            .retrieve()

                            .body(Map.class);


            if (response == null ||
                    response.isEmpty()) {

                return;
            }


            // ----------------------------------------------------
            // CREATE FINAL AI ANALYSIS
            // ----------------------------------------------------

            AIAnalysis analysis =
                    new AIAnalysis();

            analysis.setSession(session);


            analysis.setAttackType(
                    getString(
                            response,
                            "attackType",
                            "Unknown Attack"
                    )
            );


            analysis.setSeverity(
                    getString(
                            response,
                            "threatLevel",
                            "UNKNOWN"
                    )
            );


            // ----------------------------------------------------
            // RISK SCORE
            // ----------------------------------------------------

            Object scoreObject =
                    response.get("riskScore");


            int riskScore =
                    parseRiskScore(scoreObject);


            analysis.setRiskScore(
                    riskScore
            );


            // ----------------------------------------------------
            // CONFIDENCE
            // ----------------------------------------------------

            Object confidenceObject =
                    response.get("confidence");


            float confidence =
                    parseConfidence(
                            confidenceObject
                    );


            analysis.setConfidence(
                    confidence
            );


            // ----------------------------------------------------
            // SUMMARY
            // ----------------------------------------------------

            analysis.setAiSummary(
                    getString(
                            response,
                            "summary",
                            "AI analysis completed"
                    )
            );


            // ----------------------------------------------------
            // RECOMMENDATION
            // ----------------------------------------------------

            Object recommendations =
                    response.get(
                            "recommendations"
                    );


            analysis.setRecommendedAction(
                    extractRecommendation(
                            recommendations
                    )
            );


            analysis.setAnalyzedAt(
                    LocalDateTime.now()
            );


            aiAnalysisRepository.save(
                    analysis
            );


        } catch (Exception e) {

            /*
             * Do not break the honeypot pipeline if
             * AI analysis fails.
             *
             * The attack data is already stored.
             */

            System.err.println(
                    "Session AI analysis failed: "
                    + e.getMessage()
            );
        }
    }


    // ============================================================
    // SESSION CREATION
    // ============================================================

    private AttackSession getOrCreateSession(
            String sessionId,
            String ip,
            String protocol
    ) {

        return attackSessionRepository
                .findByCowrieSessionId(sessionId)
                .orElseGet(() -> {

                    AttackSession session =
                            new AttackSession();

                    session.setCowrieSessionId(
                            sessionId
                    );

                    session.setSourceIp(
                            ip != null
                                    ? ip
                                    : "127.0.0.1"
                    );

                    session.setProtocol(
                            protocol != null
                                    ? protocol.toUpperCase()
                                    : "SSH"
                    );

                    session.setLoginStatus(
                            "ATTEMPTED"
                    );

                    session.setCreatedAt(
                            LocalDateTime.now()
                    );

                    return attackSessionRepository.save(
                            session
                    );
                });
    }


    // ============================================================
    // FALLBACK ML RESULT
    // ============================================================

    private Map<String, Object> createFallbackResult(
            String command
    ) {

        Map<String, Object> result =
                new HashMap<>();


        String risk =
                evaluateFallbackRisk(command);


        result.put(
                "risk",
                risk
        );

        result.put(
                "category",
                "Command Execution"
        );

        result.put(
                "mitre_tactic",
                "T1059 - Command and Scripting Interpreter"
        );

        result.put(
                "recommendation",
                "Investigate suspicious command"
        );


        /*
         * This is a fallback score only.
         *
         * It must not be treated as ML confidence.
         */

        result.put(
                "score",
                risk.equals("HIGH")
                        ? 80
                        : risk.equals("MEDIUM")
                        ? 50
                        : 20
        );


        return result;
    }


    // ============================================================
    // SAFE STRING EXTRACTION
    // ============================================================

    private String getString(
            Map<String, Object> map,
            String key,
            String defaultValue
    ) {

        if (map == null) {
            return defaultValue;
        }

        Object value =
                map.get(key);

        if (value == null) {
            return defaultValue;
        }

        String text =
                value.toString().trim();

        return text.isEmpty()
                ? defaultValue
                : text;
    }


    // ============================================================
    // RISK SCORE PARSER
    // ============================================================

    private int parseRiskScore(
            Object value
    ) {

        if (!(value instanceof Number)) {
            return 0;
        }


        double number =
                ((Number) value).doubleValue();


        /*
         * Supports both:
         *
         * 0.0 - 1.0
         *
         * and
         *
         * 0 - 100
         */

        if (number >= 0 &&
                number <= 1) {

            number *= 100;
        }


        number =
                Math.max(
                        0,
                        Math.min(
                                100,
                                number
                        )
                );


        return (int) Math.round(number);
    }


    // ============================================================
    // CONFIDENCE PARSER
    // ============================================================

    private float parseConfidence(
            Object value
    ) {

        if (!(value instanceof Number)) {
            return 0.0f;
        }


        double number =
                ((Number) value).doubleValue();


        /*
         * Supports:
         *
         * 0.94
         *
         * and
         *
         * 94
         */

        if (number > 1 &&
                number <= 100) {

            number /= 100;
        }


        number =
                Math.max(
                        0,
                        Math.min(
                                1,
                                number
                        )
                );


        return (float) number;
    }


    // ============================================================
    // RECOMMENDATION EXTRACTION
    // ============================================================

    private String extractRecommendation(
            Object recommendations
    ) {

        if (recommendations == null) {
            return "Investigate suspicious activity";
        }


        if (recommendations instanceof List<?>) {

            List<?> list =
                    (List<?>) recommendations;

            if (!list.isEmpty()) {

                Object first =
                        list.get(0);

                if (first != null) {
                    return first.toString();
                }
            }
        }


        return recommendations.toString();
    }


    // ============================================================
    // API METHODS
    // ============================================================

    public List<AttackLog> getAllLogs() {

        return attackLogRepository
                .findAllByOrderByTimestampDesc();
    }


    public List<AttackLog> getRecentLogs() {

        return attackLogRepository
                .findTop50ByOrderByTimestampDesc();
    }


    // ============================================================
    // FALLBACK COMMAND RISK
    // ============================================================

    private String evaluateFallbackRisk(
            String command
    ) {

        if (command == null) {
            return "LOW";
        }


        String lower =
                command.toLowerCase();


        // HIGH RISK
        if (lower.contains("rm -rf") ||
                lower.contains("curl") ||
                lower.contains("wget") ||
                lower.contains("bash -i") ||
                lower.contains("nc -e") ||
                lower.contains("chmod +x") ||
                lower.contains("/etc/shadow") ||
                lower.contains("dd if=")) {

            return "HIGH";
        }


        // MEDIUM RISK
        if (lower.contains("sudo") ||
                lower.contains("cat /etc/passwd") ||
                lower.contains("uname -a") ||
                lower.contains("iptables") ||
                lower.contains("systemctl") ||
                lower.contains("netstat")) {

            return "MEDIUM";
        }


        return "LOW";
    }


    // ============================================================
    // TIMESTAMP PARSER
    // ============================================================

    private LocalDateTime parseTimestamp(
            String timestamp
    ) {

        if (timestamp == null ||
                timestamp.trim().isEmpty()) {

            return LocalDateTime.now();
        }


        try {

            return LocalDateTime.parse(
                    timestamp,
                    DateTimeFormatter.ISO_DATE_TIME
            );

        } catch (Exception e) {

            return LocalDateTime.now();
        }
    }
}