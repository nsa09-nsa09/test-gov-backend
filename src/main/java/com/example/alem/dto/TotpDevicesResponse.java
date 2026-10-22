package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TotpDevicesResponse(
    boolean success,
    String username,
    List<String> devices,
    String message
) {}
