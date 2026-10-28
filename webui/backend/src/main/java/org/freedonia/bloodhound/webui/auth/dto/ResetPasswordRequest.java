package org.freedonia.bloodhound.webui.auth.dto;

public record ResetPasswordRequest(String token, String newPassword) {}
