package org;

public class UpdateBCFKSPassword {
    public static void main(String[] args) throws Exception {
        String current = "/Users/aswanson/workbench/keycloak/testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml/sales-post-sig-transient/WEB-INF/keystore.bcfks";
        Utils.changeAllPrivateKeysInBcfksFiles(
                current,
                "keystore.bcfks",
                "averylongpassword",
                "test123",
                "averylongpassword"
        );
    }
}
