// vars/getVaultTokenForRole.groovy

def call(Map args = [:]) {
    def role = args.role ?: error("Target role not provided")

    def vaultToken

    withCredentials([
        string(credentialsId: 'vault-admin-role-id', variable: 'ROLE_ID'),
        string(credentialsId: 'vault-admin-secret-id', variable: 'SECRET_ID')
    ]) {
        def adminLoginJson = sh(
            script: '''
              set +x
              vault write -format=json auth/approle/login \
                role_id="$ROLE_ID" \
                secret_id="$SECRET_ID"
            ''',
            returnStdout: true
        ).trim()

        def vaultAdminToken = readJSON(text: adminLoginJson).auth.client_token
        if (!vaultAdminToken) {
            error("Vault admin login failed")
        }

        withEnv(["VAULT_TOKEN=${vaultAdminToken}"]) {
            def roleId = sh(
                script: "vault read -format=json auth/approle/role/${role}/role-id | jq -r .data.role_id",
                returnStdout: true
            ).trim()

            def secretId = sh(
                script: "vault write -f -format=json auth/approle/role/${role}/secret-id | jq -r .data.secret_id",
                returnStdout: true
            ).trim()

            def jenkinsLoginJson = sh(
                script: """
                  set +x
                  vault write -format=json auth/approle/login \
                    role_id="${roleId}" \
                    secret_id="${secretId}"
                """,
                returnStdout: true
            ).trim()

            vaultToken = readJSON(text: jenkinsLoginJson).auth.client_token
            if (!vaultToken) {
                error("Vault Jenkins login failed")
            }
        }
    }

    return vaultToken
}
