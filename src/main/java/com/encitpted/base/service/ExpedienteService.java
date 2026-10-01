package com.encitpted.base.service;

import com.encitpted.base.crypto.AadCodec;
import com.encitpted.base.crypto.CryptoUtils;
import com.encitpted.base.crypto.EncryptedEnvelope;
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
         *
         * Por ahora utilizamos sedena.json únicamente
         * como expediente de prueba.
         */
        JsonNode expediente =
                leerJson(EXPEDIENTE_PATH);

        /*
         * 3. Ciframos el expediente.
         */
        EncryptedEnvelope envelope =
                handle(
                        traceId,
                        INSTITUCION,
                        solicitante,
                        requesterPublicKeyBytes,
                        expediente
                );

        /*
         * 4. Convertimos los bytes obtenidos del
         *    cifrado a Base64.
         *
         * enc -> publicKey de la respuesta
         * ct  -> encryptedData
         */
        String publicKeyBase64 =
                Base64.getEncoder()
                        .encodeToString(
                                envelope.enc());

        String encryptedDataBase64 =
                Base64.getEncoder()
                        .encodeToString(
                                envelope.ct());

        log.info("======================================");
        log.info("EXPEDIENTE CIFRADO");
        log.info("INSTITUCION: {}", INSTITUCION);
        log.info("TRACE ID: {}", envelope.rid());
        log.info("SOLICITANTE: {}", solicitante);
        log.info("TIMESTAMP: {}", envelope.ts());
        log.info("ENC length: {}", envelope.enc().length);
        log.info("CT length: {}", envelope.ct().length);
        log.info("PUBLIC KEY Base64: {}", publicKeyBase64);
        log.info("ENCRYPTED DATA Base64: {}", encryptedDataBase64);
        log.info("======================================");

        /*
         * 5. Construimos la respuesta de la institución.
         */
        return ExpedienteResponseDto.builder()
                .institucion(INSTITUCION)
                .code("SUCCESS")
                .detail("Expediente encontrado")
                .encryptedData(encryptedDataBase64)
                .publicKey(publicKeyBase64)
                .timestamp(
                        String.valueOf(
                                envelope.ts()))
                .traceId(envelope.rid())
                .build();
    }

    /**
     * Cifra el expediente utilizando la clave pública
     * X25519 de la institución solicitante.
     */
    private EncryptedEnvelope handle(
            String requestId,
            String serviceName,
            String requester,
            byte[] requesterPublicKeyBytes,
            JsonNode payload) throws Exception {

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
        byte[] json = objectMapper.writeValueAsBytes(payload);

        /*
         * 3. Generamos timestamp UNIX.
         */
        long ts = Instant.now().getEpochSecond();

        /*
         * 4. Construimos el AAD.
         *
         * requestId   = X-Trace-Id
         * serviceName = SEDENA

         * requester   = X-Solicitante
         * ts          = timestamp actual
         */
        byte[] aad =
                AadCodec.build(
                        requestId,
                        serviceName,
                        requester,
                        ts);

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
         * 6. Regresamos internamente el resultado
         *    del cifrado.
         */
        return new EncryptedEnvelope(
                requestId,
                serviceName,
                ts,
                sealed.enc(),
                sealed.ciphertext()
        );
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
