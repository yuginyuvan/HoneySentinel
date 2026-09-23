package com.honeypot.backend.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "attack_logs")
@Data
public class AttackLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id")
    private String eventId;

    @Column(name = "session_uuid")
    private String sessionId;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_ip")
    private String destinationIp;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(name = "protocol")
    private String protocol;

    @Column(name = "command_input")
    private String commandInput;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "raw_json", columnDefinition = "JSON")
    private String rawJson;

    @Column(name = "timestamp")
    private LocalDateTime timestamp;
}