package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.TareaDTO;
import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.service.TareaService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService service;

    public ApiTareaController(TareaService service) {
        this.service = service;
    }

    @GetMapping
    public List<TareaDTO> misTareas(Authentication auth) {
        // Authentication llega poblado por JwtAuthFilter, exactamente como
        // llegaría si la petición viniera autenticada por sesión: el resto de
        // la aplicación no necesita saber cuál mecanismo se usó.
        return service.listarDe(auth.getName()).stream().map(TareaDTO::de).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TareaDTO crear(@Valid @RequestBody Tarea tarea, Authentication auth) {
        // Sin token CSRF: la cadena /api/** es stateless y no usa cookies
        return TareaDTO.de(service.crear(tarea, auth.getName()));
    }
}
