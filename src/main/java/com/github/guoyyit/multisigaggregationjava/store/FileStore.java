package com.github.guoyyit.multisigaggregationjava.store;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.multisigaggregationjava.config.ServiceProperties;
import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;

@Component
public class FileStore {

    private final ServiceProperties properties;
    private final ObjectMapper objectMapper;
    private Path root;

    public FileStore(ServiceProperties properties) {
        this.properties = properties;
        this.objectMapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    @PostConstruct
    public void initialize() {
        root = Path.of(properties.getStoreDir()).toAbsolutePath().normalize();
        for (String sub : List.of("keys", "sessions", "nonces", "signers", "audit")) {
            try {
                Files.createDirectories(root.resolve(sub));
            } catch (IOException ex) {
                throw new IllegalStateException("无法初始化存储目录: " + root, ex);
            }
        }
    }

    public Path root() {
        return root;
    }

    public Path keysDir() {
        return root.resolve("keys");
    }

    public Path sessionsDir() {
        return root.resolve("sessions");
    }

    public Path noncesDir() {
        return root.resolve("nonces");
    }

    public Path signersDir() {
        return root.resolve("signers");
    }

    public Path auditDir() {
        return root.resolve("audit");
    }

    public ObjectMapper mapper() {
        return objectMapper;
    }

    public void atomicWriteJson(Path target, Object value) {
        try {
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            Path temp = target.resolveSibling(
                    target.getFileName() + ".tmp-" + java.util.UUID.randomUUID());
            byte[] payload = objectMapper.writeValueAsBytes(value);
            Files.write(temp, payload,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailure) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new ServiceException(ErrorCode.INTERNAL_ERROR, "持久化写入失败: " + ex.getMessage());
        }
    }

    public <T> T readJson(Path source, Class<T> type) {
        if (!Files.exists(source)) {
            return null;
        }
        try {
            return objectMapper.readValue(Files.readAllBytes(source), type);
        } catch (IOException ex) {
            throw new ServiceException(ErrorCode.INTERNAL_ERROR, "持久化读取失败: " + ex.getMessage());
        }
    }

    public void appendLine(Path target, String line) {
        try {
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            Files.write(target, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            throw new ServiceException(ErrorCode.INTERNAL_ERROR, "追加写入失败: " + ex.getMessage());
        }
    }
}
