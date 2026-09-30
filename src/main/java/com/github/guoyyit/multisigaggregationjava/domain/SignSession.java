package com.github.guoyyit.multisigaggregationjava.domain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Mutable state of a signing session. Persisted after every transition so that
 * recovery after a crash is deterministic.
 */
public class SignSession {

    private String sessionId;
    private String messageHex;
    private List<String> participantKeyIds = new ArrayList<>();
    private Map<String, String> publicKeysHex = new LinkedHashMap<>();
    private String aggregateKeyHex;
    private SessionStatus status = SessionStatus.OPEN;
    private FailureReason failureReason;
    private int round;
    private long createdAt;
    private long deadlineAt;
    private long updatedAt;
    private Map<String, NonceCommitment> commitments = new LinkedHashMap<>();
    private Map<String, PartialSignature> partials = new LinkedHashMap<>();
    private int invalidAttempts;
    private AggregateSignature aggregateSignature;
    private boolean recoveredAfterRestart;

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getMessageHex() {
        return messageHex;
    }

    public void setMessageHex(String messageHex) {
        this.messageHex = messageHex;
    }

    public List<String> getParticipantKeyIds() {
        return participantKeyIds;
    }

    public void setParticipantKeyIds(List<String> participantKeyIds) {
        this.participantKeyIds = participantKeyIds;
    }

    public Map<String, String> getPublicKeysHex() {
        return publicKeysHex;
    }

    public void setPublicKeysHex(Map<String, String> publicKeysHex) {
        this.publicKeysHex = publicKeysHex;
    }

    public String getAggregateKeyHex() {
        return aggregateKeyHex;
    }

    public void setAggregateKeyHex(String aggregateKeyHex) {
        this.aggregateKeyHex = aggregateKeyHex;
    }

    public SessionStatus getStatus() {
        return status;
    }

    public void setStatus(SessionStatus status) {
        this.status = status;
    }

    public FailureReason getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(FailureReason failureReason) {
        this.failureReason = failureReason;
    }

    public int getRound() {
        return round;
    }

    public void setRound(int round) {
        this.round = round;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getDeadlineAt() {
        return deadlineAt;
    }

    public void setDeadlineAt(long deadlineAt) {
        this.deadlineAt = deadlineAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Map<String, NonceCommitment> getCommitments() {
        return commitments;
    }

    public void setCommitments(Map<String, NonceCommitment> commitments) {
        this.commitments = commitments;
    }

    public Map<String, PartialSignature> getPartials() {
        return partials;
    }

 public void setPartials(Map<String, PartialSignature> partials) {
        this.partials = partials;
    }

    public int getInvalidAttempts() {
        return invalidAttempts;
    }

    public void setInvalidAttempts(int invalidAttempts) {
        this.invalidAttempts = invalidAttempts;
    }

    public AggregateSignature getAggregateSignature() {
        return aggregateSignature;
    }

    public void setAggregateSignature(AggregateSignature aggregateSignature) {
        this.aggregateSignature = aggregateSignature;
    }

    public boolean isRecoveredAfterRestart() {
        return recoveredAfterRestart;
    }

    public void setRecoveredAfterRestart(boolean recoveredAfterRestart) {
        this.recoveredAfterRestart = recoveredAfterRestart;
    }
}
