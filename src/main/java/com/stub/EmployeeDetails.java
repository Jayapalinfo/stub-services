package com.stub;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;

@Getter
@Setter
@Builder
public class EmployeeDetails {
    private String userId;
    private String userName;
    private String emailAddress;
    private String organizationId;
    private String[] adRoles;
    private String[] rwaFunctions;


    public static EmployeeDetails parse(String cookie) {
        String[] splittedCookie = cookie.split(",");
        EmployeeDetails employeeDetails = EmployeeDetails.builder()
                .userName(splittedCookie[0])
                .userId(splittedCookie[1])
                .emailAddress(splittedCookie[2])
                .organizationId(splittedCookie[3])
                .adRoles(toAdRoles(splittedCookie[4]))
                .rwaFunctions(toFunctions(splittedCookie[5], splittedCookie[1]))
                .build();
        return employeeDetails;
    }

    protected static String[] toFunctions(String functionsString, String userId) {
        var functions = functionsString.replace("RW_", "").split("\\|");
        return Arrays.stream(functions).map(a -> String.format("Application;%s;%s", a, userId)).toArray(String[]::new);
    }

    protected static String[] toAdRoles(String rolesString) {
        return rolesString.replace("AD_", "").split("\\|");
    }
}
