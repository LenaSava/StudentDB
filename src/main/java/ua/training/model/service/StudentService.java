package ua.training.model.service;

import ua.training.model.dao.DaoFactory;
import ua.training.model.dao.StudentDao;
import ua.training.model.entity.Student;

import java.util.List;

public class StudentService {

    DaoFactory daoFactory = DaoFactory.getInstance();

    public List<Student> getAllStudents(){
        try (StudentDao dao = daoFactory.createStudentDao()) {
            return dao.findAll();
        }
    }
}
