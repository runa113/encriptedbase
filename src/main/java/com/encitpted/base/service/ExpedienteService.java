package com.encitpted.base.service;

import com.encitpted.base.crypto.AadCodec;
import com.encitpted.base.crypto.CryptoUtils;
import com.encitpted.base.crypto.HpkeCodec;
import com.encitpted.base.dto.ExpedienteRequestDto;
import com.encitpted.base.dto.ExpedienteResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExpedienteService {

    /*
     * Institución que representa este simulador.
     */
    private static final String INSTITUCION = "SEDENA";

    /*
     * Expediente utilizado temporalmente para las pruebas.
     */
    private static final String EXPEDIENTE_PATH =
            "/expedientes/sedena.json";

    /*
     * Debe ser el mismo INFO utilizado por quien
     * posteriormente realizará el descifrado.
     */
    private static final byte[] INFO =
            "secure-demo/v1"
                    .getBytes(StandardCharsets.UTF_8);

    private final ObjectMapper objectMapper;

    public ExpedienteResponseDto obtenerExpediente (
            String apiKey,
            String traceId,
            String solicitante,
            ExpedienteRequestDto request) throws Exception {

        log.info("======================================");
        log.info("Solicitud recibida por {}", INSTITUCION);
        log.info("TRACE ID: {}", traceId);
        log.info("SOLICITANTE: {}", solicitante);
        log.info("CURP: {}", request.getCurpPaciente());
        log.info("INSTITUCION REQUEST: {}", request.getInstitucion());
        log.info("======================================");

        /*
         * 1. Decodificamos la clave pública que llega
         *    en el request.
         */
        byte[] requesterPublicKeyBytes =
                Base64.getDecoder()
                        .decode(request.getPublicKey());

        log.info(
                "PUBLIC KEY REQUEST length: {}",
                requesterPublicKeyBytes.length
        );

        /*
         * 2. Leemos el expediente.
         */
        JsonNode expediente =
                leerJson(EXPEDIENTE_PATH);

        /*
         * 3. Ciframos y regresamos directamente
         *    la respuesta de SEDENA.
         */
        return cifrarExpediente(
                traceId,
                INSTITUCION,
                solicitante,
                requesterPublicKeyBytes,
                expediente
        );
    }

    /**
     * Cifra el expediente utilizando la clave pública
     * X25519 de la institución solicitante.
     */
    private ExpedienteResponseDto cifrarExpediente(
            String traceId,
            String institucion,
            String solicitante,
            byte[] requesterPublicKeyBytes,
            JsonNode expediente) throws Exception {

        /*
         * 1. Convertimos los bytes recibidos en una
         *    clave pública X25519.
         */
        X25519PublicKeyParameters requesterPublicKey =
                CryptoUtils.decodePublicKey(
                        requesterPublicKeyBytes);

        /*
         * 2. Serializamos todo el expediente JSON.
         */
        byte[] json =
                objectMapper.writeValueAsBytes(expediente);

        /*
         * 3. Generamos timestamp UNIX.
         */
        long timestamp =
                Instant.now().getEpochSecond();

        /*
         * 4. Construimos el AAD.
         *
         * traceId     = X-Trace-Id
         * institucion = SEDENA
         * solicitante = X-Solicitante
         * timestamp   = timestamp actual
         */
        byte[] aad =
                AadCodec.build(
                        traceId,
                        institucion,
                        solicitante,
                        timestamp);

        /*
         * 5. Ciframos mediante HPKE.
         */
        HpkeCodec.Sealed sealed =
                HpkeCodec.seal(
                        requesterPublicKey,
                        INFO,
                        aad,
                        json);

        /*
         * 6. Convertimos el resultado del cifrado
         *    a Base64.
         *
         * enc        -> publicKey
         * ciphertext -> encryptedData
         */
        String publicKeyBase64 =
                Base64.getEncoder()
                        .encodeToString(sealed.enc());

        String encryptedDataBase64 =
                Base64.getEncoder()
                        .encodeToString(sealed.ciphertext());

        log.info("======================================");
        log.info("EXPEDIENTE CIFRADO");
        log.info("INSTITUCION: {}", institucion);
        log.info("TRACE ID: {}", traceId);
        log.info("SOLICITANTE: {}", solicitante);
        log.info("TIMESTAMP: {}", timestamp);
        log.info("ENC length: {}", sealed.enc().length);
        log.info(
                "CT length: {}",
                sealed.ciphertext().length);
        log.info("======================================");

        /*
         * 7. Construimos directamente el DTO final.
         */
        return ExpedienteResponseDto.builder()
                .institucion(institucion)
                .code("SUCCESS")
                .detail("Expediente encontrado")
                .encryptedData(encryptedDataBase64)
                .publicKey(publicKeyBase64)
                .timestamp(String.valueOf(timestamp))
                .traceId(traceId)
                .build();
    }

    /**
     * Lee el expediente JSON almacenado en resources.
     */
    private JsonNode leerJson(String ruta) {

        try (InputStream inputStream = getClass().getResourceAsStream(ruta)) {

            if (inputStream == null) {
                throw new IllegalStateException("No se encontró el archivo: " + ruta);
            }

            return objectMapper.readTree(inputStream);

        } catch (IOException e) {

            throw new IllegalStateException("Error al leer el archivo: " + ruta, e);
        }
    }
}
