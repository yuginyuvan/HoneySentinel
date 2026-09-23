package com.honeypot.analytics.dto;

import java.util.List;
import java.util.Map;

public class DashboardStatsDTO {

    private long totalAttacks;
    private long failedLogins;
    private long successfulLogins;
    private long uniqueAttackerIps;
    private String threatLevel;
    private String primaryAttackType;
    private double riskScore;
    private String recommendation;
    private List<Map<String, Object>> timeline;
    private List<Map<String, Object>> recentLogs;
    private List<Map<String, Object>> topCredentials;

    public DashboardStatsDTO() {
    }

    public DashboardStatsDTO(
            long totalAttacks,
            long failedLogins,
            long successfulLogins,
            long uniqueAttackerIps,
            String threatLevel,
            String primaryAttackType,
            double riskScore,
            String recommendation,
            List<Map<String, Object>> timeline,
            List<Map<String, Object>> recentLogs,
            List<Map<String, Object>> topCredentials) {

        this.totalAttacks = totalAttacks;
        this.failedLogins = failedLogins;
        this.successfulLogins = successfulLogins;
        this.uniqueAttackerIps = uniqueAttackerIps;
        this.threatLevel = threatLevel;
        this.primaryAttackType = primaryAttackType;
        this.riskScore = riskScore;
        this.recommendation = recommendation;
        this.timeline = timeline;
        this.recentLogs = recentLogs;
        this.topCredentials = topCredentials;
    }

    public long getTotalAttacks() {
        return totalAttacks;
    }

    public void setTotalAttacks(long totalAttacks) {
        this.totalAttacks = totalAttacks;
    }

    public long getFailedLogins() {
        return failedLogins;
    }

    public void setFailedLogins(long failedLogins) {
        this.failedLogins = failedLogins;
    }

    public long getSuccessfulLogins() {
        return successfulLogins;
    }

    public void setSuccessfulLogins(long successfulLogins) {
        this.successfulLogins = successfulLogins;
    }

    public long getUniqueAttackerIps() {
        return uniqueAttackerIps;
    }

    public void setUniqueAttackerIps(long uniqueAttackerIps) {
        this.uniqueAttackerIps = uniqueAttackerIps;
    }

    public String getThreatLevel() {
        return threatLevel;
    }

    public void setThreatLevel(String threatLevel) {
        this.threatLevel = threatLevel;
    }

    public String getPrimaryAttackType() {
        return primaryAttackType;
    }

    public void setPrimaryAttackType(String primaryAttackType) {
        this.primaryAttackType = primaryAttackType;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(double riskScore) {
        this.riskScore = riskScore;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public List<Map<String, Object>> getTimeline() {
        return timeline;
    }

    public void setTimeline(List<Map<String, Object>> timeline) {
        this.timeline = timeline;
    }

    public List<Map<String, Object>> getRecentLogs() {
        return recentLogs;
    }

    public void setRecentLogs(List<Map<String, Object>> recentLogs) {
        this.recentLogs = recentLogs;
    }

    public List<Map<String, Object>> getTopCredentials() {
        return topCredentials;
    }

    public void setTopCredentials(List<Map<String, Object>> topCredentials) {
        this.topCredentials = topCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private long totalAttacks;
        private long failedLogins;
        private long successfulLogins;
        private long uniqueAttackerIps;
        private String threatLevel;
        private String primaryAttackType;
        private double riskScore;
        private String recommendation;
        private List<Map<String, Object>> timeline;
        private List<Map<String, Object>> recentLogs;
        private List<Map<String, Object>> topCredentials;

        public Builder totalAttacks(long value) {
            this.totalAttacks = value;
            return this;
        }

        public Builder failedLogins(long value) {
            this.failedLogins = value;
            return this;
        }

        public Builder successfulLogins(long value) {
            this.successfulLogins = value;
            return this;
        }

        public Builder uniqueAttackerIps(long value) {
            this.uniqueAttackerIps = value;
            return this;
        }

        public Builder threatLevel(String value) {
            this.threatLevel = value;
            return this;
        }

        public Builder primaryAttackType(String value) {
            this.primaryAttackType = value;
            return this;
        }

        public Builder riskScore(double value) {
            this.riskScore = value;
            return this;
        }

        public Builder recommendation(String value) {
            this.recommendation = value;
            return this;
        }

        public Builder timeline(List<Map<String, Object>> value) {
            this.timeline = value;
            return this;
        }

        public Builder recentLogs(List<Map<String, Object>> value) {
            this.recentLogs = value;
            return this;
        }

        public Builder topCredentials(List<Map<String, Object>> value) {
            this.topCredentials = value;
            return this;
        }

        public DashboardStatsDTO build() {
            return new DashboardStatsDTO(
                    totalAttacks,
                    failedLogins,
                    successfulLogins,
                    uniqueAttackerIps,
                    threatLevel,
                    primaryAttackType,
                    riskScore,
                    recommendation,
                    timeline,
                    recentLogs,
                    topCredentials
            );
        }
    }
}