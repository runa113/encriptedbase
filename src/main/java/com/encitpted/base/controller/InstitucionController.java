package com.encitpted.base.controller;

import com.encitpted.base.dto.ExpedienteRequestDto;
import com.encitpted.base.dto.ExpedienteResponseDto;
import com.encitpted.base.service.ExpedienteService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/expedientes")
@RequiredArgsConstructor
public class InstitucionController {

    private final ExpedienteService expedienteService;

    @PostMapping("/instituciones")
    public ResponseEntity<ExpedienteResponseDto> obtenerExpediente(
            @RequestHeader("X-Api-Key") String apiKey,
            @RequestHeader("X-Trace-Id") String traceId,
            @RequestHeader("X-Solicitante") String solicitante,
            @Valid @RequestBody ExpedienteRequestDto request)
            throws Exception {

        ExpedienteResponseDto response =
                expedienteService.obtenerExpediente(
                        apiKey,
                        traceId,
                        solicitante,
                        request);

        return ResponseEntity.ok(response);
    }
}
