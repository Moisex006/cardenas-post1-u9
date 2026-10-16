package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
public class UsuarioService {

    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;

    public UsuarioService(UsuarioRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Transactional
    public void registrar(Usuario usuario) {
        if (repo.existsByEmail(usuario.getEmail())) {
            throw new IllegalStateException("El correo ya está registrado");
        }
        // Los campos que no vienen del formulario se fijan aquí: un POST
        // manipulado con id, rol o activo no puede sobrescribir otro usuario
        // ni registrarse como ADMIN (mass assignment)
        usuario.setId(null);
        usuario.setActivo(true);
        usuario.setRol("ROLE_USER"); // rol por defecto
        usuario.setContrasenia(encoder.encode(usuario.getContrasenia()));
        repo.save(usuario);
    }

    public Usuario buscarPorEmail(String email) {
        return repo.findByEmail(email)
            .orElseThrow(() -> new IllegalStateException("Usuario no encontrado: " + email));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<Usuario> listarTodos() {
        return repo.findAll();
    }
}
