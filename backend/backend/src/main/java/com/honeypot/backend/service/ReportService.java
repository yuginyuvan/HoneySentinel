package com.honeypot.backend.service;

import com.honeypot.backend.model.AIAnalysis;
import com.honeypot.backend.model.AttackLog;
import com.honeypot.backend.model.AttackSession;
import com.honeypot.backend.model.CommandLog;

import com.honeypot.backend.repository.AIAnalysisRepository;
import com.honeypot.backend.repository.AttackLogRepository;
import com.honeypot.backend.repository.AttackSessionRepository;
import com.honeypot.backend.repository.CommandLogRepository;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;

import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ReportService {

    private final AttackLogRepository attackLogRepository;
    private final AttackSessionRepository attackSessionRepository;
    private final CommandLogRepository commandLogRepository;
    private final AIAnalysisRepository aiAnalysisRepository;

    public ReportService(
            AttackLogRepository attackLogRepository,
            AttackSessionRepository attackSessionRepository,
            CommandLogRepository commandLogRepository,
            AIAnalysisRepository aiAnalysisRepository) {

        this.attackLogRepository = attackLogRepository;
        this.attackSessionRepository = attackSessionRepository;
        this.commandLogRepository = commandLogRepository;
        this.aiAnalysisRepository = aiAnalysisRepository;
    }

    public byte[] generateReport() {

        List<AttackLog> attackLogs =
                attackLogRepository.findAllByOrderByTimestampDesc();

        List<AttackSession> sessions =
                attackSessionRepository.findAllByOrderByCreatedAtDesc();

        List<CommandLog> commands =
                commandLogRepository.findAllByOrderByCommandTimeDesc();

        List<AIAnalysis> analyses =
                aiAnalysisRepository.findAll();

        try {

            ByteArrayOutputStream outputStream =
                    new ByteArrayOutputStream();

            Document document =
                    new Document(PageSize.A4, 36, 36, 40, 40);

            PdfWriter.getInstance(document, outputStream);

            document.open();

            // =========================================================
            // FONTS
            // =========================================================

            Font titleFont = FontFactory.getFont(
                    FontFactory.HELVETICA_BOLD,
                    20
            );

            Font headingFont = FontFactory.getFont(
                    FontFactory.HELVETICA_BOLD,
                    14
            );

            Font normalFont = FontFactory.getFont(
                    FontFactory.HELVETICA,
                    10
            );

            Font smallFont = FontFactory.getFont(
                    FontFactory.HELVETICA,
                    8
            );

            // =========================================================
            // DATE FORMAT
            // =========================================================

            DateTimeFormatter formatter =
                    DateTimeFormatter.ofPattern(
                            "dd-MM-yyyy HH:mm:ss"
                    );

            // =========================================================
            // TITLE
            // =========================================================

            Paragraph title = new Paragraph(
                    "AI HONEYPOT THREAT INTELLIGENCE REPORT",
                    titleFont
            );

            title.setAlignment(Element.ALIGN_CENTER);

            document.add(title);

            document.add(new Paragraph(" "));

            Paragraph generatedTime = new Paragraph(
                    "Report Generated: "
                            + LocalDateTime.now().format(formatter),
                    normalFont
            );

            generatedTime.setAlignment(Element.ALIGN_CENTER);

            document.add(generatedTime);

            document.add(new Paragraph(" "));

            // =========================================================
            // 1. EXECUTIVE SUMMARY
            // =========================================================

            document.add(
                    new Paragraph(
                            "1. EXECUTIVE SUMMARY",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            Set<String> uniqueIPs = attackLogs.stream()
                    .map(AttackLog::getSourceIp)
                    .filter(Objects::nonNull)
                    .filter(ip -> !ip.isBlank())
                    .collect(Collectors.toSet());

            long successfulLogins = sessions.stream()
                    .filter(s -> s.getLoginStatus() != null)
                    .filter(s ->
                            s.getLoginStatus()
                                    .equalsIgnoreCase("success"))
                    .count();

            long failedLogins = sessions.stream()
                    .filter(s -> s.getLoginStatus() != null)
                    .filter(s ->
                            s.getLoginStatus()
                                    .equalsIgnoreCase("failed"))
                    .count();

            int highRiskCount = (int) analyses.stream()
                    .filter(a -> a.getSeverity() != null)
                    .filter(a ->
                            a.getSeverity()
                                    .equalsIgnoreCase("HIGH"))
                    .count();

            PdfPTable summaryTable =
                    new PdfPTable(2);

            summaryTable.setWidthPercentage(100);

            addCell(
                    summaryTable,
                    "Metric",
                    headingFont
            );

            addCell(
                    summaryTable,
                    "Value",
                    headingFont
            );

            addCell(
                    summaryTable,
                    "Total Attack Events",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(attackLogs.size()),
                    normalFont
            );

            addCell(
                    summaryTable,
                    "Unique Attacker IPs",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(uniqueIPs.size()),
                    normalFont
            );

            addCell(
                    summaryTable,
                    "Total Sessions",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(sessions.size()),
                    normalFont
            );

            addCell(
                    summaryTable,
                    "Successful Logins",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(successfulLogins),
                    normalFont
            );

            addCell(
                    summaryTable,
                    "Failed Logins",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(failedLogins),
                    normalFont
            );

            addCell(
                    summaryTable,
                    "High Risk Analyses",
                    normalFont
            );

            addCell(
                    summaryTable,
                    String.valueOf(highRiskCount),
                    normalFont
            );

            document.add(summaryTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 2. ATTACK CLASSIFICATION
            // =========================================================

            document.add(
                    new Paragraph(
                            "2. ATTACK CLASSIFICATION",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            Map<String, Long> attackTypes =
                    analyses.stream()
                            .map(AIAnalysis::getAttackType)
                            .filter(Objects::nonNull)
                            .filter(type -> !type.isBlank())
                            .collect(Collectors.groupingBy(
                                    String::trim,
                                    TreeMap::new,
                                    Collectors.counting()
                            ));

            PdfPTable attackTable =
                    new PdfPTable(2);

            attackTable.setWidthPercentage(100);

            addCell(
                    attackTable,
                    "Attack Type",
                    headingFont
            );

            addCell(
                    attackTable,
                    "Count",
                    headingFont
            );

            if (attackTypes.isEmpty()) {

                addCell(
                        attackTable,
                        "No AI classifications available",
                        normalFont
                );

                addCell(
                        attackTable,
                        "0",
                        normalFont
                );

            } else {

                for (Map.Entry<String, Long> entry :
                        attackTypes.entrySet()) {

                    addCell(
                            attackTable,
                            entry.getKey(),
                            normalFont
                    );

                    addCell(
                            attackTable,
                            String.valueOf(entry.getValue()),
                            normalFont
                    );
                }
            }

            document.add(attackTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 3. THREAT SEVERITY
            // =========================================================

            document.add(
                    new Paragraph(
                            "3. THREAT SEVERITY",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            Map<String, Long> severityCounts =
                    analyses.stream()
                            .map(AIAnalysis::getSeverity)
                            .filter(Objects::nonNull)
                            .filter(severity -> !severity.isBlank())
                            .collect(Collectors.groupingBy(
                                    String::trim,
                                    TreeMap::new,
                                    Collectors.counting()
                            ));

            PdfPTable severityTable =
                    new PdfPTable(2);

            severityTable.setWidthPercentage(100);

            addCell(
                    severityTable,
                    "Severity",
                    headingFont
            );

            addCell(
                    severityTable,
                    "Count",
                    headingFont
            );

            for (Map.Entry<String, Long> entry :
                    severityCounts.entrySet()) {

                addCell(
                        severityTable,
                        entry.getKey(),
                        normalFont
                );

                addCell(
                        severityTable,
                        String.valueOf(entry.getValue()),
                        normalFont
                );
            }

            if (severityCounts.isEmpty()) {

                addCell(
                        severityTable,
                        "No severity data",
                        normalFont
                );

                addCell(
                        severityTable,
                        "0",
                        normalFont
                );
            }

            document.add(severityTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 4. TOP ATTACKER IP ADDRESSES
            // =========================================================

            document.add(
                    new Paragraph(
                            "4. TOP ATTACKER IP ADDRESSES",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            Map<String, Long> ipCounts =
                    attackLogs.stream()
                            .map(AttackLog::getSourceIp)
                            .filter(Objects::nonNull)
                            .filter(ip -> !ip.isBlank())
                            .collect(Collectors.groupingBy(
                                    String::trim,
                                    Collectors.counting()
                            ));

            List<Map.Entry<String, Long>> topIPs =
                    ipCounts.entrySet()
                            .stream()
                            .sorted(
                                    Map.Entry
                                            .<String, Long>comparingByValue()
                                            .reversed()
                            )
                            .limit(10)
                            .toList();

            PdfPTable ipTable =
                    new PdfPTable(2);

            ipTable.setWidthPercentage(100);

            addCell(
                    ipTable,
                    "Source IP",
                    headingFont
            );

            addCell(
                    ipTable,
                    "Events",
                    headingFont
            );

            for (Map.Entry<String, Long> entry : topIPs) {

                addCell(
                        ipTable,
                        entry.getKey(),
                        normalFont
                );

                addCell(
                        ipTable,
                        String.valueOf(entry.getValue()),
                        normalFont
                );
            }

            if (topIPs.isEmpty()) {

                addCell(
                        ipTable,
                        "No attacker IP data",
                        normalFont
                );

                addCell(
                        ipTable,
                        "0",
                        normalFont
                );
            }

            document.add(ipTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 5. COMMANDS OBSERVED
            // =========================================================

            document.add(
                    new Paragraph(
                            "5. COMMANDS OBSERVED",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            PdfPTable commandTable =
                    new PdfPTable(4);

            commandTable.setWidthPercentage(100);

            addCell(
                    commandTable,
                    "Command",
                    headingFont
            );

            addCell(
                    commandTable,
                    "Risk",
                    headingFont
            );

            addCell(
                    commandTable,
                    "Working Directory",
                    headingFont
            );

            addCell(
                    commandTable,
                    "Time",
                    headingFont
            );

            commands.stream()
                    .limit(30)
                    .forEach(command -> {

                        addCell(
                                commandTable,
                                safe(command.getCommand()),
                                smallFont
                        );

                        addCell(
                                commandTable,
                                safe(command.getRiskLevel()),
                                smallFont
                        );

                        addCell(
                                commandTable,
                                safe(command.getWorkingDirectory()),
                                smallFont
                        );

                        addCell(
                                commandTable,
                                command.getCommandTime() != null
                                        ? command.getCommandTime()
                                        .format(formatter)
                                        : "-",
                                smallFont
                        );
                    });

            if (commands.isEmpty()) {

                addCell(
                        commandTable,
                        "No commands recorded",
                        normalFont
                );

                addCell(
                        commandTable,
                        "-",
                        normalFont
                );

                addCell(
                        commandTable,
                        "-",
                        normalFont
                );

                addCell(
                        commandTable,
                        "-",
                        normalFont
                );
            }

            document.add(commandTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 6. AI ANALYSIS
            // =========================================================

            document.add(
                    new Paragraph(
                            "6. AI ANALYSIS",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            PdfPTable aiTable =
                    new PdfPTable(5);

            aiTable.setWidthPercentage(100);

            addCell(
                    aiTable,
                    "Attack Type",
                    headingFont
            );

            addCell(
                    aiTable,
                    "Severity",
                    headingFont
            );

            addCell(
                    aiTable,
                    "Risk Score",
                    headingFont
            );

            addCell(
                    aiTable,
                    "Confidence",
                    headingFont
            );

            addCell(
                    aiTable,
                    "Analyzed At",
                    headingFont
            );

            analyses.stream()
                    .sorted(
                            Comparator.comparing(
                                    AIAnalysis::getAnalyzedAt,
                                    Comparator.nullsLast(
                                            Comparator.reverseOrder()
                                    )
                            )
                    )
                    .limit(30)
                    .forEach(analysis -> {

                        addCell(
                                aiTable,
                                safe(analysis.getAttackType()),
                                smallFont
                        );

                        addCell(
                                aiTable,
                                safe(analysis.getSeverity()),
                                smallFont
                        );

                        addCell(
                                aiTable,
                                analysis.getRiskScore() != null
                                        ? String.valueOf(
                                                analysis.getRiskScore())
                                        : "-",
                                smallFont
                        );

                        addCell(
                                aiTable,
                                analysis.getConfidence() != null
                                        ? String.format(
                                                "%.2f",
                                                analysis.getConfidence())
                                        : "-",
                                smallFont
                        );

                        addCell(
                                aiTable,
                                analysis.getAnalyzedAt() != null
                                        ? analysis.getAnalyzedAt()
                                        .format(formatter)
                                        : "-",
                                smallFont
                        );
                    });

            if (analyses.isEmpty()) {

                for (int i = 0; i < 5; i++) {

                    addCell(
                            aiTable,
                            i == 0
                                    ? "No AI analysis available"
                                    : "-",
                            normalFont
                    );
                }
            }

            document.add(aiTable);

            document.add(new Paragraph(" "));

            // =========================================================
            // 7. SECURITY RECOMMENDATIONS
            // =========================================================

            document.add(
                    new Paragraph(
                            "7. SECURITY RECOMMENDATIONS",
                            headingFont
                    )
            );

            document.add(new Paragraph(" "));

            Set<String> recommendations =
                    analyses.stream()
                            .map(AIAnalysis::getRecommendedAction)
                            .filter(Objects::nonNull)
                            .filter(action -> !action.isBlank())
                            .limit(10)
                            .collect(Collectors.toCollection(
                                    LinkedHashSet::new
                            ));

            if (recommendations.isEmpty()) {

                document.add(
                        new Paragraph(
                                "No AI-generated recommendations "
                                        + "are currently available.",
                                normalFont
                        )
                );

            } else {

                for (String recommendation :
                        recommendations) {

                    document.add(
                            new Paragraph(
                                    "• " + recommendation,
                                    normalFont
                            )
                    );
                }
            }

            document.add(new Paragraph(" "));

            // =========================================================
            // FOOTER
            // =========================================================

            Paragraph footer =
                    new Paragraph(
                            "Generated by AI Honeypot Threat "
                                    + "Intelligence System",
                            smallFont
                    );

            footer.setAlignment(Element.ALIGN_CENTER);

            document.add(footer);

            document.close();

            return outputStream.toByteArray();

        } catch (Exception e) {

            throw new RuntimeException(
                    "Failed to generate threat intelligence report",
                    e
            );
        }
    }

    // =============================================================
    // HELPER METHOD
    // =============================================================

    private void addCell(
            PdfPTable table,
            String text,
            Font font) {

        table.addCell(
                new Phrase(
                        text == null ? "-" : text,
                        font
                )
        );
    }

    private String safe(String value) {

        if (value == null || value.isBlank()) {
            return "-";
        }

        return value;
    }
}