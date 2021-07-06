package com.mitchma91.mitchManuel.Exception;

public class UsernameOrIdNotFound extends Exception {
	
/**
	 * 
	 */
	private static final long serialVersionUID = 880278141511461079L;

public UsernameOrIdNotFound() {
	super("Usuario o Id No Encontrado");
}

public UsernameOrIdNotFound(String message) {
	super(message);
}
}
