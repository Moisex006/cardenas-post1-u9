package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
public class TareaService {

    private final TareaRepository repo;
    private final UsuarioRepository usuarioRepo;

    public TareaService(TareaRepository repo, UsuarioRepository usuarioRepo) {
        this.repo = repo;
        this.usuarioRepo = usuarioRepo;
    }

    // ADMIN ve todas las tareas
    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> listarTodas() {
        return repo.findAll();
    }

    // USER solo las suyas. Se compara con authentication.name (el correo),
    // que existe tanto en la sesión de las vistas como en el token JWT de la API
    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<Tarea> listarDe(String email) {
        return repo.findByPropietarioEmail(email);
    }

    // Búsqueda sobre todas las tareas: solo ADMIN
    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> buscar(String texto) {
        return repo.buscarPorTitulo(texto); // @Query parametrizado — seguro
    }

    // Búsqueda limitada a las tareas propias: un USER no ve tareas ajenas
    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<Tarea> buscarDe(String texto, String email) {
        return repo.buscarPorTituloDe(texto, email); // @Query parametrizado — seguro
    }

    @Transactional
    public Tarea crear(Tarea tarea, String email) {
        Usuario propietario = usuarioRepo.findByEmail(email)
            .orElseThrow(() -> new IllegalStateException("Usuario no encontrado: " + email));
        tarea.setId(null);
        tarea.setPropietario(propietario);
        return repo.save(tarea);
    }

    @Transactional
    public void cambiarEstado(Long id) {
        Tarea tarea = obtenerConAcceso(id);
        tarea.setCompletada(!tarea.isCompletada());
    }

    @Transactional
    public void eliminar(Long id) {
        repo.delete(obtenerConAcceso(id));
    }

    // El propietario o un ADMIN pueden modificar la tarea; cualquier otro
    // usuario recibe 403 aunque conozca el id
    private Tarea obtenerConAcceso(Long id) {
        Tarea tarea = repo.findById(id)
            .orElseThrow(() -> new IllegalStateException("Tarea no encontrada: " + id));
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean esAdmin = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!esAdmin && !tarea.getPropietario().getEmail().equals(auth.getName())) {
            throw new AccessDeniedException("No puede modificar tareas de otro usuario");
        }
        return tarea;
    }
}
