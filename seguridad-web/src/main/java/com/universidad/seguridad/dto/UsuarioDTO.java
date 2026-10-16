package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Usuario;

// Usuario expuesto por la API, sin la contraseña
public record UsuarioDTO(Long id, String nombre, String email, String rol, boolean activo) {

    public static UsuarioDTO de(Usuario u) {
        return new UsuarioDTO(u.getId(), u.getNombre(), u.getEmail(), u.getRol(), u.isActivo());
    }
}
