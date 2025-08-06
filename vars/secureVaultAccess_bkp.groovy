def call(Map args = [:]) {
    def role = args.role ?: error("Target role not provided")

    def creds = [:]

    withCredentials([
        string(credentialsId: 'vault-admin-role-id', variable: 'ROLE_ID'),
        string(credentialsId: 'vault-admin-secret-id', variable: 'SECRET_ID')
    ]) {
        // Step 1: Admin login to Vault
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
            // Step 2: Get target AppRole creds
            def roleId = sh(
                script: "vault read -format=json auth/approle/role/${role}/role-id | jq -r .data.role_id",
                returnStdout: true
            ).trim()

            def secretId = sh(
                script: "vault write -f -format=json auth/approle/role/${role}/secret-id | jq -r .data.secret_id",
                returnStdout: true
            ).trim()

            // Step 3: Login as Jenkins AppRole
            def jenkinsLoginJson = sh(
                script: """
                  set +x
                  vault write -format=json auth/approle/login \
                    role_id="${roleId}" \
                    secret_id="${secretId}"
                """,
                returnStdout: true
            ).trim()

            def vaultJenkinsToken = readJSON(text: jenkinsLoginJson).auth.client_token
            if (!vaultJenkinsToken) {
                error("Vault Jenkins login failed")
            }

            withEnv(["VAULT_TOKEN=${vaultJenkinsToken}"]) {
                // Step 4: Get AWS creds from Vault
                def awsCredsJson = sh(
                    script: "vault read -format=json aws/sts/ec2-admin",
                    returnStdout: true
                ).trim()

                def awsCreds = readJSON(text: awsCredsJson)
                creds.access_key = awsCreds.data.access_key
                creds.secret_key = awsCreds.data.secret_key
                creds.security_token = awsCreds.data.security_token
            }
        }
    }

    return creds
}
