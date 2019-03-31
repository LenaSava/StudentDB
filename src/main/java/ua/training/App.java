package ua.training;

import java.sql.*;

public class App {
    public static void main(String[] args) throws SQLException {
        System.out.println("Assist".hashCode());

        System.out.println("Hello!");
        Connection con =
                DriverManager.
                        getConnection(  "jdbc:"+
                                        "mysql:"+
                                        "//localhost:3306/"+
                                        "mystudentdb",
                                "root" ,
                                "root");

        Statement query = con.createStatement();
        ResultSet rs = query.executeQuery("SELECT * FROM teacher");
        while( rs.next()) {
            System.out.println(rs.getString("name"));}

    }
}
