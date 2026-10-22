package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TotpConfirmResponse(
    boolean success,
    String code,
    String message
) {}
