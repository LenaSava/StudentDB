package ua.training.model.dao;

import ua.training.model.entity.Teacher;

import java.util.Optional;

public interface TeacherDao extends GenericDao<Teacher> {

    Optional<Teacher> findByName(String name);
}
