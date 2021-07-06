package com.mitchma91.mitchManuel.service;

import javax.validation.Valid;

import com.mitchma91.mitchManuel.Exception.UsernameOrIdNotFound;
import com.mitchma91.mitchManuel.dto.ChangePasswordForm;
import com.mitchma91.mitchManuel.entity.User;

public interface UserService {

	public Iterable<User> getAllUsers();
	public User createUser(@Valid User user) throws Exception;
	User getUserById(Long id) throws Exception ;
	public User updateUser(User user) throws Exception;
	public void deleteUser(Long id) throws UsernameOrIdNotFound;
	public User changePassword(ChangePasswordForm form) throws Exception;
}
