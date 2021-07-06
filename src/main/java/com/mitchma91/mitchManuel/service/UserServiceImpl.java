package com.mitchma91.mitchManuel.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

import javax.validation.Valid;

import com.mitchma91.mitchManuel.dto.ChangePasswordForm;
import com.mitchma91.mitchManuel.entity.User;
import com.mitchma91.mitchManuel.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService{

	@Autowired
	UserRepository repository;
	
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Override
	public Iterable<User> getAllUsers(){
		return repository.findAll();
	}
	
	
	
	private boolean checkUsernameAvailable(User user) throws Exception{
		Optional<User> userFound= repository.findByUsername(user.getUsername());
		if(userFound.isPresent()) {
			throw new Exception("Username no disponible");
		}
		return true;
	}

	
	private boolean checkPasswordValid(User user) throws Exception{
		if (user.getConfirmPassword() == null || user.getConfirmPassword().isEmpty()) {
			throw new Exception("Confirm Password es obligatorio");
		}
		if(!user.getPassword().equals(user.getConfirmPassword())) {
			throw new Exception("Password y Confirm Password no son iguales");
		}
		return true;
	}


	
	@Override
	public User createUser(User user) throws Exception{
		if (checkUsernameAvailable(user) && checkPasswordValid(user)) {
			user= repository.save(user);
		}
		return user;
	}
	
	@Override
	public User getUserById(Long id) throws Exception {
		User user = repository.findById(id).orElseThrow(() -> new Exception("Usuario no existe"));
		return user;
	}
	
	@Override
	@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
	public User updateUser(User fromUser) throws Exception {
		User toUser = getUserById(fromUser.getId());
		mapUser(fromUser, toUser);
		return repository.save(toUser);
	}
	
	/**
	 * Map everythin but the password.
	 * @param from
	 * @param to
	 */
	protected void mapUser(User from,User to) {
		to.setUsername(from.getUsername());
		to.setFirstName(from.getFirstName());
		to.setLastName(from.getLastName());
		to.setEmail(from.getEmail());
		to.setRoles(from.getRoles());
	}
	
	@Override
	@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
	public void deleteUser(Long id) throws Exception {
		User user = repository.findById(id)
				.orElseThrow(() -> new Exception("UsernotFound in deleteUser -"+this.getClass().getName()));

		repository.delete(user);
	}
	
	public boolean loggedUserHasRole(String role) {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		UserDetails loggedUser = null;
		Object roles = null; 
		if (principal instanceof UserDetails) {
			loggedUser = (UserDetails) principal;
		
			roles = loggedUser.getAuthorities().stream()
					.filter(x -> role.equals(x.getAuthority() ))      
					.findFirst().orElse(null); //loggedUser = null;
		}
		return roles != null ?true :false;
	}
	
	@Override
	public User changePassword(ChangePasswordForm form) throws Exception{
		User user = getUserById(form.getId());
				
		
		if( !isLoggedUserADMIN() && form.getCurrentPassword().equals(form.getCurrentPassword())) {
			throw new Exception("Current Password Incorrect.");
		}
		
		if ( form.getCurrentPassword().equals(form.getNewPassword())) {
			throw new Exception("El nuevo password debe ser diferente al password actual!");
		}
		
		if( !form.getNewPassword().equals(form.getConfirmPassword())) {
			throw new Exception("El nuevo password y el confirmado no coinciden!");
		}
		
		String encodePassword = bCryptPasswordEncoder.encode(form.getNewPassword());
		user.setPassword(encodePassword);
		return repository.save(user);
	}
	
	private boolean isLoggedUserADMIN() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		UserDetails loggedUser = null;
		if (principal instanceof UserDetails) {
			loggedUser = (UserDetails) principal;

			loggedUser.getAuthorities().stream()
					.filter(x -> "ADMIN".equals(x.getAuthority() ))      
					.findFirst().orElse(null); //loggedUser = null;
		}
		return loggedUser != null ?true :false;
	}
}
