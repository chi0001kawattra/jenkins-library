def call(Map args = [:]) {
    // Validate role
    def role = args.role ?: error("Target role not provided")
    if (!role.matches('^[a-zA-Z0-9_-]+$')) {
        error("Invalid role name: ${role}")
    }

    def vaultToken = ''
    def generatedSecretIdAccessor = ''
    
    withCredentials([
        string(credentialsId: args.bootstrapRoleId ?: 'vault-admin-role-id', variable: 'ROLE_ID'),
        string(credentialsId: args.bootstrapSecretId ?: 'vault-admin-secret-id', variable: 'SECRET_ID')
    ]) {
        // Bootstrap login to Vault
        def bootstrapTokenJson = sh(
            script: '''
              set +x
              vault write -format=json auth/approle/login \
                role_id="$ROLE_ID" \
                secret_id="$SECRET_ID"
            ''',
            returnStdout: true
        ).trim()

        def bootstrapToken = ''
        try {
            bootstrapToken = readJSON(text: bootstrapTokenJson).auth.client_token
        } catch (Exception e) {
            echo "Failed to parse bootstrap login response: ${bootstrapTokenJson}"
            error("Vault bootstrap login failed due to JSON parsing error")
        }

        if (!bootstrapToken) {
            echo "Bootstrap login failed: ${bootstrapTokenJson}"
            error("Vault bootstrap login failed — token missing")
        }

        withEnv(["VAULT_TOKEN=${bootstrapToken}"]) {
            retry(count: 3) {
                sleep time: 2, unit: 'SECONDS'

                // Get role_id
                def roleIdJson = sh(
                    script: "vault read -format=json auth/approle/role/${role}/role-id",
                    returnStdout: true
                ).trim()
                def roleId = readJSON(text: roleIdJson).data.role_id

                // Generate a scoped secret_id
                def secretIdJson = sh(
                    script: "vault write -f -format=json auth/approle/role/${role}/secret-id",
                    returnStdout: true
                ).trim()
                def secretIdData = readJSON(text: secretIdJson).data
                def secretId = secretIdData.secret_id
                generatedSecretIdAccessor = secretIdData.secret_id_accessor

                // Login using target AppRole
                def loginJson = sh(
                    script: """
                        set +x
                        vault write -format=json auth/approle/login \\
                          role_id='${roleId}' \\
                          secret_id='${secretId}'
                    """,
                    returnStdout: true
                ).trim()
                vaultToken = readJSON(text: loginJson).auth.client_token
            }
        }

        // Revoke the secret_id accessor (cleanup)
        if (generatedSecretIdAccessor) {
            try {
                sh(
                    script: """
                        VAULT_TOKEN=${bootstrapToken} vault write auth/approle/role/${role}/secret-id-accessor/destroy secret_id_accessor=${generatedSecretIdAccessor}
                    """
                )
                echo "Cleaned up secret_id_accessor for role '${role}'"
            } catch (Exception e) {
                echo "WARNING: Failed to revoke secret_id_accessor — ${e.message}"
            }
        }
    }

    return vaultToken
}
