package ua.training.model.dao.mapper;

import ua.training.model.entity.Student;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

public class StudentMapper implements ObjectMapper<Student> {


    @Override
    public Student extractFromResultSet(ResultSet rs) throws SQLException {
        Student student = new Student();
        student.setId(rs.getInt("idstuden"));
        student.setName(rs.getString("studen.name"));
        student.setGroupe(rs.getInt("group"));
        return student;
    }

    @Override
    public Student makeUnique(Map<Integer, Student> cache,
                              Student student) {
        cache.putIfAbsent(student.getId(), student);
        return cache.get(student.getId());
    }
}
