package com.encitpted.base.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ExpedienteRequestDto {

    @NotBlank
    @Size(min = 18, max = 18)
    private String curpPaciente;

    @NotBlank
    private String publicKey;

    @NotBlank
    @Pattern(regexp = "^(?!-)(?!.*--)[A-Z-]+(?<!-)$")
    private String institucion;
}
