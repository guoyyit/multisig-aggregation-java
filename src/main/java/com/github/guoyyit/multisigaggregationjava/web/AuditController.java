package com.github.guoyyit.multisigaggregationjava.web;

import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditLog auditLog;

    public AuditController(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @GetMapping
    public Map<String, Object> entries() {
        List<AuditEntry> entries = auditLog.entries();
        return Map.of("entries", entries, "total", entries.size());
    }
}
