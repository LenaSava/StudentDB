package ua.training.model.service;

import ua.training.model.dao.DaoFactory;
import ua.training.model.dao.TeacherDao;
import ua.training.model.entity.Teacher;

import java.util.Optional;

public class TeacherService {

    DaoFactory daoFactory = DaoFactory.getInstance();
    public Optional<Teacher> login(String name){
        Optional<Teacher> result; //= Optional.empty();
        try(TeacherDao teacherDao = daoFactory.createTeacherDao()){
            result = teacherDao.findByName(name);
        }
        return result;
    }
}
