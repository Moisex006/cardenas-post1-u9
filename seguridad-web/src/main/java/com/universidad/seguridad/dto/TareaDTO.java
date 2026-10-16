package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Tarea;

// Lo que la API devuelve de una tarea. Se usa un DTO en vez de la entidad
// porque serializar Tarea incluiría su propietario completo, con el hash
// de la contraseña.
public record TareaDTO(Long id, String titulo, String descripcion, boolean completada, String propietario) {

    public static TareaDTO de(Tarea t) {
        return new TareaDTO(t.getId(), t.getTitulo(), t.getDescripcion(),
            t.isCompletada(), t.getPropietario().getEmail());
    }
}
