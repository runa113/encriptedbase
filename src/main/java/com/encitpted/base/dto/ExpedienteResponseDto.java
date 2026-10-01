package com.encitpted.base.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ExpedienteResponseDto {

    private String institucion;

    private String code;

    private String detail;

    private String encryptedData;

    private String publicKey;

    private String timestamp;

    @JsonProperty("trace_id")
    private String traceId;
}
