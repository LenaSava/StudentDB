package ua.training.controller.commands;

import javax.servlet.http.HttpServletRequest;

public class AddStudent implements Command {
    @Override
    public String execute(HttpServletRequest request) {
        return "/WEB-INF/addStudent.html";
    }
}
