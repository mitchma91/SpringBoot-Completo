package com.mitchma91.mitchManuel.controller;

import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.Mapping;
//import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.mitchma91.mitchManuel.Exception.CustomeFieldValidationException;
import com.mitchma91.mitchManuel.Exception.UsernameOrIdNotFound;
import com.mitchma91.mitchManuel.dto.ChangePasswordForm;
import com.mitchma91.mitchManuel.entity.User;
import com.mitchma91.mitchManuel.repository.RoleRepository;
import com.mitchma91.mitchManuel.service.UserService;


@Controller
public class UserController {

	@Autowired
	UserService userService;
	@Autowired
	RoleRepository roleRepository;
	
	
	
	@GetMapping({"/", "login"})
	public String index() {
		return "index";
	}
	
	@GetMapping("/userForm")
	public String getUserForm(Model model) {
		model.addAttribute("userForm", new User());
		model.addAttribute("roles",roleRepository.findAll());
		model.addAttribute("userList", userService.getAllUsers());
		model.addAttribute("listTab","active");
		return "user-form/user-view";
	}	
	@PostMapping("/userForm")
	public String createUser(@Valid @ModelAttribute("userForm")User user, BindingResult result, ModelMap model) {
		if(result.hasErrors()) {
			model.addAttribute("userForm", user);
			model.addAttribute("formTab","active");
		}else {
			try {
				userService.createUser(user);
				model.addAttribute("userForm", new User());
				//model.addAttribute("userForm", user);
				model.addAttribute("listTab","active");

			} catch (CustomeFieldValidationException cfve) {
				result.rejectValue(cfve.getFieldName(), null, cfve.getMessage());
				model.addAttribute("userForm", user);
				model.addAttribute("formTab","active");
				model.addAttribute("userList", userService.getAllUsers());
				model.addAttribute("roles",roleRepository.findAll());
			}
			
			catch (Exception e) {
				model.addAttribute("formErrorMessage",e.getMessage());
				model.addAttribute("userForm", user);
				model.addAttribute("formTab","active");
				model.addAttribute("userList", userService.getAllUsers());
				model.addAttribute("roles",roleRepository.findAll());
			}
		}

		model.addAttribute("userList", userService.getAllUsers());
		model.addAttribute("roles",roleRepository.findAll());
		return "user-form/user-view";
	}
	
	@GetMapping("/editUser/{id}")
	public String getEditUserForm(Model model, @PathVariable(name="id") Long id) throws Exception {
		User user = userService.getUserById(id);
		
		
		model.addAttribute("userList", userService.getAllUsers());
		model.addAttribute("roles",roleRepository.findAll());
		model.addAttribute("userForm", user);
		model.addAttribute("formTab","active");//Activa el tab del formulario.
		
		model.addAttribute("editMode",true);//Mira siguiente seccion para mas informacion
		model.addAttribute("passwordForm",new ChangePasswordForm(user.getId()));
		
		return "user-form/user-view";
	}
	@PostMapping("/editUser")
	public String postEditUserForm(@Valid @ModelAttribute("userForm")User user, BindingResult result, ModelMap model) {
		if(result.hasErrors()) {
			model.addAttribute("userForm", user);
			model.addAttribute("formTab","active");
			model.addAttribute("editMode","true");
		}else {
			try {
				userService.updateUser(user);
				model.addAttribute("userForm", new User());
				model.addAttribute("listTab","active");
			} catch (Exception e) {
				
				model.addAttribute("formErrorMessage",e.getMessage());
				model.addAttribute("userForm", user);
				model.addAttribute("formTab","active");
				model.addAttribute("userList", userService.getAllUsers());
				model.addAttribute("roles",roleRepository.findAll());
				model.addAttribute("editMode","true");
				model.addAttribute("passwordForm",new ChangePasswordForm(user.getId()));
			}
		}
		
		model.addAttribute("userList", userService.getAllUsers());
		model.addAttribute("roles",roleRepository.findAll());
		return "user-form/user-view";
		
	}
	
	@GetMapping("/userForm/cancel")
	public String cancelEditUser(ModelMap model) {
		return "redirect:/userForm";
	}
	
	@GetMapping("/deleteUser/{id}")
	public String deleteUser(Model model, @PathVariable(name="id") Long id) {
		try {
			userService.deleteUser(id);
		} catch (UsernameOrIdNotFound e) {
			model.addAttribute("listErrorMessage",e.getMessage());
		}
		return getUserForm(model);
	}
	
	@PostMapping("/editUser/changePassword")
	public ResponseEntity postEditUseChangePassword(@Valid @RequestBody ChangePasswordForm form, Errors errors) {
		try {
			//If error, just return a 400 bad request, along with the error message
	        if (errors.hasErrors()) {
	            String result = errors.getAllErrors()
	                        .stream().map(x -> x.getDefaultMessage())
	                        .collect(Collectors.joining(""));

	            throw new Exception(result);
	        }
			userService.changePassword(form);
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
		return ResponseEntity.ok("success");
	}
}
