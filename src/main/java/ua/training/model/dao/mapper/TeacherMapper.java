package ua.training.model.dao.mapper;

import ua.training.model.entity.Teacher;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

public class TeacherMapper implements ObjectMapper<Teacher> {

    @Override
    public Teacher extractFromResultSet(ResultSet rs) throws SQLException {
        Teacher teacher = new Teacher();
        teacher.setId(rs.getInt("id"));
        teacher.setName(rs.getString("name"));
        teacher.setCourse(rs.getString("course"));
        teacher.setRoom(rs.getInt("room"));
        teacher.setPassHash(rs.getString("hash_pass"));
        return teacher;
    }

    public Teacher makeUnique(Map<Integer, Teacher> cache,
                              Teacher teacher) {
        cache.putIfAbsent(teacher.getId(), teacher);
        return cache.get(teacher.getId());
    }
}
