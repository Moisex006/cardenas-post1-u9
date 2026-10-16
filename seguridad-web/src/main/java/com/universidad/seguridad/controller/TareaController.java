package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.service.TareaService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Controller
@RequestMapping("/tareas")
public class TareaController {

    private final TareaService service;

    public TareaController(TareaService service) {
        this.service = service;
    }

    @GetMapping
    public String listar(@RequestParam(required = false) String q, Model model, Authentication auth) {
        model.addAttribute("tareas", consultar(q, auth));
        model.addAttribute("q", q);
        model.addAttribute("nueva", new Tarea());
        return "tareas/lista";
    }

    @PostMapping
    public String crear(@Valid @ModelAttribute("nueva") Tarea tarea, BindingResult result,
                        Model model, Authentication auth) {
        if (result.hasErrors()) {
            model.addAttribute("tareas", consultar(null, auth));
            return "tareas/lista";
        }
        service.crear(tarea, auth.getName());
        return "redirect:/tareas";
    }

    @PostMapping("/{id}/estado")
    public String cambiarEstado(@PathVariable Long id) {
        service.cambiarEstado(id);
        return "redirect:/tareas";
    }

    @PostMapping("/{id}/eliminar")
    public String eliminar(@PathVariable Long id) {
        service.eliminar(id);
        return "redirect:/tareas";
    }

    // ADMIN consulta todas las tareas; USER solo las propias
    private List<Tarea> consultar(String q, Authentication auth) {
        boolean esAdmin = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean hayBusqueda = q != null && !q.isBlank();
        if (esAdmin) {
            return hayBusqueda ? service.buscar(q) : service.listarTodas();
        }
        return hayBusqueda ? service.buscarDe(q, auth.getName()) : service.listarDe(auth.getName());
    }
}
