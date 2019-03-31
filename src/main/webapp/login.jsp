<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>




<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Doctor App</title>
</head>
    <body>
        <h2>
            Hello WEB! <br/>

        </h2>

        <br/>

        <br>
        <form method="GET" action="${pageContext.request.contextPath}/api/teacher-login">
            <input type="text" name="name"/><br>
            <input type="password" name = "pass"/><br>
            <input type="submit"/>
        </form>

    </body>
</html>