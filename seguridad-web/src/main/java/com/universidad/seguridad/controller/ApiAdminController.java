package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.service.UsuarioService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

// Ruta /api/admin/**: apiFilterChain exige ROLE_ADMIN, que llega en el
// claim "rol" del JWT
@RestController
@RequestMapping("/api/admin")
public class ApiAdminController {

    private final UsuarioService service;

    public ApiAdminController(UsuarioService service) {
        this.service = service;
    }

    @GetMapping("/usuarios")
    public List<UsuarioDTO> usuarios() {
        return service.listarTodos().stream().map(UsuarioDTO::de).toList();
    }
}
