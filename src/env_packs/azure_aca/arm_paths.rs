//! ARM URL construction (pure). The api-version is pinned here and nowhere else.

/// `Microsoft.App/containerApps` api-version (`NEEDS_LIVE`, see the decision record).
pub(crate) const API_VERSION: &str = "2024-03-01";
/// `Microsoft.Authorization/permissions` api-version.
pub(crate) const AUTHORIZATION_API_VERSION: &str = "2022-04-01";
pub(crate) const ARM_HOST: &str = "https://management.azure.com";

/// Where the deployer works: fixed by the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AzureScope {
    pub subscription: String,
    pub resource_group: String,
    pub environment: String,
}

impl AzureScope {
    fn rg(&self) -> String {
        format!(
            "{ARM_HOST}/subscriptions/{}/resourceGroups/{}",
            self.subscription, self.resource_group
        )
    }

    pub(crate) fn app(&self, name: &str) -> String {
        format!(
            "{}/providers/Microsoft.App/containerApps/{name}?api-version={API_VERSION}",
            self.rg()
        )
    }

    pub(crate) fn list_secrets(&self, name: &str) -> String {
        format!(
            "{}/providers/Microsoft.App/containerApps/{name}/listSecrets?api-version={API_VERSION}",
            self.rg()
        )
    }

    pub(crate) fn revision(&self, app: &str, revision: &str) -> String {
        format!(
            "{}/providers/Microsoft.App/containerApps/{app}/revisions/{revision}?api-version={API_VERSION}",
            self.rg()
        )
    }

    pub(crate) fn deactivate(&self, app: &str, revision: &str) -> String {
        format!(
            "{}/providers/Microsoft.App/containerApps/{app}/revisions/{revision}/deactivate?api-version={API_VERSION}",
            self.rg()
        )
    }

    pub(crate) fn environment(&self) -> String {
        format!(
            "{}/providers/Microsoft.App/managedEnvironments/{}?api-version={API_VERSION}",
            self.rg(),
            self.environment
        )
    }

    pub(crate) fn permissions(&self) -> String {
        format!(
            "{}/providers/Microsoft.Authorization/permissions?api-version={AUTHORIZATION_API_VERSION}",
            self.rg()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn scope() -> AzureScope {
        AzureScope {
            subscription: "sub".into(),
            resource_group: "rg".into(),
            environment: "env".into(),
        }
    }

    #[test]
    fn urls_carry_scope_and_the_pinned_api_version() {
        let s = scope();
        assert_eq!(
            s.app("gtc-x"),
            "https://management.azure.com/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps/gtc-x?api-version=2024-03-01"
        );
        assert!(s.list_secrets("a").contains("/a/listSecrets?"));
        assert!(
            s.deactivate("a", "a--r1")
                .contains("/revisions/a--r1/deactivate?")
        );
        assert!(s.environment().contains("managedEnvironments/env?"));
        assert!(
            s.permissions()
                .contains("Microsoft.Authorization/permissions?api-version=2022-04-01")
        );
    }
}
