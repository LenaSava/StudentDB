package ua.training.controller.commands;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ua.training.model.entity.Teacher;
import ua.training.model.service.TeacherService;

import javax.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;



public class LoginTeacherCommand implements Command {

    private static final Logger logger = LogManager.getLogger(LoginTeacherCommand.class);
    private TeacherService teacherService ;

    public LoginTeacherCommand(TeacherService teacherService) {
        this.teacherService = teacherService;
    }

    @Override
    public String execute(HttpServletRequest request) {
        String name = request.getParameter("name");
        String pass = request.getParameter("pass");
        if( name == null || name.equals("") || pass == null || pass.equals("")){
            return "/login.jsp";
        }
        Optional<Teacher> teacher = teacherService.login(name);
        if( teacher.isPresent() && teacher.get().getPassHash().equals(getPwdHash(pass))){
            request.getSession().setAttribute("teacher" , teacher.get());
            logger.info("Teacher "+ name+" logged successfully.");
            return "/WEB-INF/studentlist.jsp";

        }
        logger.info("Invalid attempt of login user:'"+ name+"'");
        return "/login.jsp";
    }

    private static String getPwdHash(String passwordToHash) {
        String generatedPassword = null;
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            //Add password bytes to digest
            md.update(passwordToHash.getBytes());
            //Get the hash's bytes
            byte[] bytes = md.digest();
            //This bytes[] has bytes in decimal format;
            //Convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            //Get complete hashed password in hex format
            generatedPassword = sb.toString();
        }
        catch (NoSuchAlgorithmException e)
        {
            logger.error("Cannot validate password: "+ e.getMessage());
        }
        return generatedPassword;
    }
}
